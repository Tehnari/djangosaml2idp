import base64
import logging
import time
import uuid
from typing import Dict, List, Optional, Union

from django.conf import settings
from django.contrib.auth import get_user_model, logout
from django.core.cache import cache
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import (ImproperlyConfigured, ObjectDoesNotExist,
                                    PermissionDenied, ValidationError)
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.template.backends.django import Template
from django.template.exceptions import (TemplateDoesNotExist,
                                        TemplateSyntaxError)
from django.template.loader import get_template
from django.urls import reverse
from django.utils.datastructures import MultiValueDictKeyError
from django.utils.decorators import method_decorator
from django.utils.module_loading import import_string
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.authn_context import PASSWORD, AuthnBroker, authn_context_class_ref
from saml2.ident import NameID
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED

from .error_views import error_cbv
from .idp import IDP
from .models import ServiceProvider
from .processors import BaseProcessor
from .utils import repr_saml, verify_request_signature

logger = logging.getLogger(__name__)

User = get_user_model()


def store_params_in_session(request: HttpRequest) -> str:
    """ Gathers the SAML parameters from the HTTP request and store them in the session.
    
    Also stores in cache as fallback in case session cookies are lost during cross-site redirects.
    This provides resilience against browser cookie issues (SameSite, third-party cookie blocking, etc.)
    
    Returns:
        str: UUID state parameter for cache lookup and cookie storage
    """
    if request.method == 'POST':
        # future TODO: parse also SOAP and PAOS format from POST
        passed_data = request.POST
        binding = BINDING_HTTP_POST
    else:
        passed_data = request.GET
        binding = BINDING_HTTP_REDIRECT

    try:
        saml_request = passed_data['SAMLRequest']
    except (KeyError, MultiValueDictKeyError) as e:
        logger.error(
            f"SAML2 SSO Entry: Missing SAMLRequest parameter. "
            f"Method: {request.method}, Path: {request.path}, "
            f"User-Agent: {request.META.get('HTTP_USER_AGENT', 'Unknown')}, "
            f"Referer: {request.META.get('HTTP_REFERER', 'None')}"
        )
        raise ValidationError(_('not a valid SAMLRequest: {}').format(repr(e)))

    relay_state = passed_data.get('RelayState', '')
    
    # Generate UUID state parameter for hybrid storage (session + cookie + cache)
    state_uuid = str(uuid.uuid4())
    
    # Store in session (primary storage) - keep existing keys for backward compatibility
    try:
        request.session['Binding'] = binding
        request.session['SAMLRequest'] = saml_request
        request.session['RelayState'] = relay_state
        # Store state UUID in session for hybrid approach
        request.session['saml2_auth_state_uuid'] = state_uuid
        # Note: Django's session middleware saves automatically, but explicit save ensures immediate persistence
        # This helps with cross-site redirects where session continuity is critical
        try:
            request.session.save()
        except Exception as save_error:
            # Log but don't fail - session middleware will handle save later
            logger.debug(f"SAML2 SSO Entry: Session save warning (non-critical): {save_error}")
        
        logger.debug(
            f"SAML2 SSO Entry: Stored in session. "
            f"Session key: {request.session.session_key}, "
            f"State UUID: {state_uuid}, "
            f"Binding: {binding}, "
            f"RelayState: {relay_state[:50] if relay_state else 'None'}"
        )
    except Exception as session_error:
        logger.warning(
            f"SAML2 SSO Entry: Failed to store in session: {session_error}. "
            f"Session key: {request.session.session_key if hasattr(request.session, 'session_key') else 'None'}"
        )
        # Continue to cache fallback
    
    # Store in cache with UUID key (for cross-site cookie issues)
    # This replaces the old session-key-based cache storage
    try:
        cache_key = f'saml2_request_{state_uuid}'
        cache_data = {
            'SAMLRequest': saml_request,
            'Binding': binding,
            'RelayState': relay_state,
            'timestamp': time.time(),
        }
        # Store for 10 minutes (enough time for authentication flow)
        cache.set(cache_key, cache_data, timeout=600)
        logger.debug(f"SAML2 SSO Entry: Stored in cache with UUID key. Cache key: {cache_key}")
    except Exception as cache_error:
        logger.warning(f"SAML2 SSO Entry: Failed to store in cache: {cache_error}")
        # Non-critical, continue with session only
    
    return state_uuid


@never_cache
@csrf_exempt
@require_http_methods(["GET", "POST"])
def sso_entry(request: HttpRequest, *args, **kwargs) -> HttpResponse:
    """ Entrypoint view for SSO. Store the saml info in the request session
        and redirects to the login_process view.
    """
    try:
        state_uuid = store_params_in_session(request)
    except ValidationError as e:
        return error_cbv.handle_error(request, e, status_code=400)

    # Use defensive access in case session save failed (values still in session object)
    binding = request.session.get('Binding', BINDING_HTTP_POST)
    saml_request = request.session.get('SAMLRequest')
    
    logger.debug(f"SSO requested to IDP with binding {binding}")
    if saml_request:
        logger.debug(f"--- SAML request [\n{repr_saml(saml_request, b64=True)}] ---")
    else:
        logger.warning("SAML2 SSO Entry: SAMLRequest missing from session after storage attempt")

    # Create redirect response
    response = HttpResponseRedirect(reverse('djangosaml2idp:saml_login_process'))
    
    # Set state UUID cookie for hybrid storage approach (survives cross-site redirects)
    # Cookie attributes: SameSite=None (required for cross-site), Secure=True (required for SameSite=None),
    # HttpOnly=True (security), max_age=600 (10 minutes, matches cache timeout)
    response.set_cookie(
        'saml2_auth_state',
        state_uuid,
        max_age=600,  # 10 minutes
        path='/',
        domain=None,  # Use default domain
        secure=True,  # Required for SameSite=None
        httponly=True,  # Security: prevent JavaScript access
        samesite='None'  # Required for cross-site redirects
    )
    
    logger.debug(
        f"SAML2 SSO Entry: Set state cookie. State UUID: {state_uuid}, "
        f"Cookie: saml2_auth_state"
    )
    
    return response


def check_access(processor: BaseProcessor, request: HttpRequest) -> None:
    """ Check if user has access to the service of this SP. Raises a PermissionDenied exception if not.
    """
    if not processor.has_access(request):
        raise PermissionDenied(_("You do not have access to this resource"))


def get_sp_config(sp_entity_id: str) -> ServiceProvider:
    """ Get a dict with the configuration for a SP according to the SAML_IDP_SPCONFIG settings.
        Raises an exception if no SP matching the given entity id can be found.
    """
    try:
        sp = ServiceProvider.objects.get(entity_id=sp_entity_id, active=True)
    except ObjectDoesNotExist:
        raise ImproperlyConfigured(_("No active Service Provider object matching the entity_id '{}' found").format(sp_entity_id))
    return sp


def get_authn(req_info=None):
    req_authn_context = req_info.message.requested_authn_context if req_info else PASSWORD
    broker = AuthnBroker()
    broker.add(authn_context_class_ref(req_authn_context), "")
    return broker.get_authn_by_accr(req_authn_context)


def build_authn_response(user: User, authn, resp_args, service_provider: ServiceProvider) -> list:  # type: ignore
    """ pysaml2 server.Server.create_authn_response wrapper
    """
    policy = resp_args.get('name_id_policy', None)
    if policy is None:
        name_id_format = NAMEID_FORMAT_UNSPECIFIED
    else:
        name_id_format = policy.format

    idp_server = IDP.load()
    idp_name_id_format_list = idp_server.config.getattr("name_id_format", "idp") or [NAMEID_FORMAT_UNSPECIFIED]

    if name_id_format not in idp_name_id_format_list:
        raise ImproperlyConfigured(_('SP requested a name_id_format that is not supported in the IDP: {}').format(name_id_format))

    processor: BaseProcessor = service_provider.processor  # type: ignore
    user_id = processor.get_user_id(user, name_id_format, service_provider, idp_server.config)
    name_id = NameID(format=name_id_format, sp_name_qualifier=service_provider.entity_id, text=user_id)

    return idp_server.create_authn_response(
        authn=authn,
        identity=processor.create_identity(user, service_provider.attribute_mapping),
        name_id=name_id,
        userid=user_id,
        sp_entity_id=service_provider.entity_id,
        # Signing
        sign_response=service_provider.sign_response,
        sign_assertion=service_provider.sign_assertion,
        sign_alg=service_provider.signing_algorithm,
        digest_alg=service_provider.digest_algorithm,
        # Encryption
        encrypt_assertion=service_provider.encrypt_saml_responses,
        encrypted_advice_attributes=service_provider.encrypt_saml_responses,
        **resp_args
    )


class IdPHandlerViewMixin:
    """ Contains some methods used by multiple views """

    def render_login_html_to_string(self, context=None, request=None, using=None):
        """ Render the html response for the login action. Can be using a custom html template if set on the view. """
        default_login_template_name = 'djangosaml2idp/login.html'
        custom_login_template_name = getattr(self, 'login_html_template', None)

        if custom_login_template_name:
            template = self._fetch_custom_template(custom_login_template_name, default_login_template_name, using)
            return template.render(context, request)

        template = get_template(default_login_template_name, using=using)
        return template.render(context, request)

    @staticmethod
    def _fetch_custom_template(custom_name: str, default_name: str, using: Optional[str] = None) -> Template:
        """ Grabs the custom login template. Falls back to default if issues arise. """
        try:
            template = get_template(custom_name, using=using)
        except (TemplateDoesNotExist, TemplateSyntaxError) as e:
            logger.error(
                'Specified template {} cannot be used due to: {}. Falling back to default login template {}'.format(
                    custom_name, str(e), default_name))
            template = get_template(default_name, using=using)
        return template

    def create_html_response(self, request: HttpRequest, binding, authn_resp, destination, relay_state):
        """ Login form for SSO
        """
        if binding == BINDING_HTTP_POST:
            context = {
                "acs_url": destination,
                "saml_response": base64.b64encode(str(authn_resp).encode()).decode(),
                "relay_state": relay_state,
            }
            html_response = {
                "data": self.render_login_html_to_string(context=context, request=request),
                "type": "POST",
            }
        else:
            idp_server = IDP.load()
            http_args = idp_server.apply_binding(
                binding=binding,
                msg_str=authn_resp,
                destination=destination,
                relay_state=relay_state,
                response=True)

            logger.debug('http args are: %s' % http_args)
            html_response = {
                "data": http_args['headers'][0][1],
                "type": "REDIRECT",
            }
        return html_response

    def render_response(self, request: HttpRequest, html_response, processor: BaseProcessor = None) -> HttpResponse:
        """ Return either a response as redirect to MultiFactorView or as html with self-submitting form to log in.
        """
        if not processor:
            # In case of SLO, where processor isn't relevant
            if html_response['type'] == 'POST':
                return HttpResponse(html_response['data'])
            else:
                return HttpResponseRedirect(html_response['data'])

        request.session['saml_data'] = html_response

        if processor.enable_multifactor(request.user):
            logger.debug("Redirecting to process_multi_factor")
            return HttpResponseRedirect(reverse('djangosaml2idp:saml_multi_factor'))

        # No multifactor
        logger.debug("Performing SAML redirect")
        if html_response['type'] == 'POST':
            return HttpResponse(html_response['data'])
        else:
            return HttpResponseRedirect(html_response['data'])


@method_decorator(never_cache, name='dispatch')
class LoginProcessView(LoginRequiredMixin, IdPHandlerViewMixin, View):
    """ View which processes the actual SAML request and returns a self-submitting form with the SAML response.
        The login_required decorator ensures the user authenticates first on the IdP using 'normal' ways.
    """

    def get(self, request, *args, **kwargs):
        # Log request details for debugging
        logger.debug(
            f"SAML2 Login Process: Request received. "
            f"Path: {request.path}, "
            f"Method: {request.method}, "
            f"Session key: {request.session.session_key if hasattr(request.session, 'session_key') else 'None'}, "
            f"User: {request.user.username if request.user.is_authenticated else 'Anonymous'}, "
            f"User-Agent: {request.META.get('HTTP_USER_AGENT', 'Unknown')[:100]}"
        )
        
        # Try to get SAMLRequest from session (primary source)
        saml_request = None
        binding = BINDING_HTTP_POST
        relay_state = ''
        
        try:
            saml_request = request.session['SAMLRequest']
            binding = request.session.get('Binding', BINDING_HTTP_POST)
            relay_state = request.session.get('RelayState', '')
            logger.debug(
                f"SAML2 Login Process: Retrieved from session. "
                f"Binding: {binding}, "
                f"RelayState present: {bool(relay_state)}"
            )
        except KeyError as session_error:
            # Session data missing - try hybrid cache fallback (UUID-based)
            logger.warning(
                f"SAML2 Login Process: SAMLRequest missing from session (KeyError: {session_error}). "
                f"Session key: {request.session.session_key if hasattr(request.session, 'session_key') else 'None'}, "
                f"Session keys available: {list(request.session.keys())}, "
                f"Attempting hybrid cache fallback (UUID-based)..."
            )
            
            # Hybrid approach: Try UUID-based cache lookup
            state_uuid_from_session = request.session.get('saml2_auth_state_uuid')
            state_uuid_from_cookie = request.COOKIES.get('saml2_auth_state')
            
            # Security validation: Prefer session UUID, validate if both exist
            state_uuid = None
            if state_uuid_from_session:
                state_uuid = state_uuid_from_session
                if state_uuid_from_cookie and state_uuid_from_cookie != state_uuid_from_session:
                    logger.warning(
                        f"SAML2 Login Process: UUID mismatch detected. "
                        f"Session UUID: {state_uuid_from_session[:8]}..., "
                        f"Cookie UUID: {state_uuid_from_cookie[:8]}... "
                        f"Using session UUID (more secure). Possible stale cookie or session hijacking attempt."
                    )
            elif state_uuid_from_cookie:
                # Validate UUID format
                try:
                    uuid.UUID(state_uuid_from_cookie)  # Validate format
                    state_uuid = state_uuid_from_cookie
                    logger.debug(
                        f"SAML2 Login Process: Using cookie UUID (session UUID missing). "
                        f"Cookie UUID: {state_uuid[:8]}..."
                    )
                except (ValueError, TypeError) as uuid_error:
                    logger.error(
                        f"SAML2 Login Process: Invalid UUID format in cookie: {uuid_error}. "
                        f"Cookie value: {state_uuid_from_cookie[:20]}..."
                    )
                    state_uuid = None
            
            # Try UUID-based cache lookup
            if state_uuid:
                try:
                    cache_key = f'saml2_request_{state_uuid}'
                    cache_data = cache.get(cache_key)
                    if cache_data:
                        # Validate cache data structure before using
                        cached_saml_request = cache_data.get('SAMLRequest')
                        cached_binding = cache_data.get('Binding')
                        cached_relay_state = cache_data.get('RelayState', '')
                        
                        if cached_saml_request and cached_binding:
                            saml_request = cached_saml_request
                            binding = cached_binding
                            relay_state = cached_relay_state
                            logger.info(
                                f"SAML2 Login Process: Retrieved from UUID-based cache. "
                                f"Cache key: {cache_key}, "
                                f"Binding: {binding}, "
                                f"UUID source: {'session' if state_uuid_from_session else 'cookie'}"
                            )
                            # Restore to session for future use
                            try:
                                request.session['SAMLRequest'] = saml_request
                                request.session['Binding'] = binding
                                request.session['RelayState'] = relay_state
                                request.session['saml2_auth_state_uuid'] = state_uuid  # Restore UUID too
                                request.session.save()
                                logger.debug("SAML2 Login Process: Restored cache data to session")
                            except Exception as restore_error:
                                logger.warning(f"SAML2 Login Process: Failed to restore cache data to session: {restore_error}")
                        else:
                            logger.error(
                                f"SAML2 Login Process: UUID-based cache data incomplete. "
                                f"Cache key: {cache_key}, "
                                f"Has SAMLRequest: {bool(cached_saml_request)}, "
                                f"Has Binding: {bool(cached_binding)}"
                            )
                    else:
                        logger.warning(
                            f"SAML2 Login Process: UUID-based cache lookup failed. "
                            f"Cache key: {cache_key} not found. "
                            f"Attempting session-key-based fallback..."
                        )
                except Exception as cache_error:
                    logger.error(f"SAML2 Login Process: UUID-based cache lookup error: {cache_error}")
            
            # Final fallback: Try old session-key-based cache lookup (backward compatibility)
            if not saml_request:
                session_key = request.session.session_key
                if session_key:
                    try:
                        cache_key = f'saml2_request_{session_key}'
                        cache_data = cache.get(cache_key)
                        if cache_data:
                            cached_saml_request = cache_data.get('SAMLRequest')
                            cached_binding = cache_data.get('Binding')
                            cached_relay_state = cache_data.get('RelayState', '')
                            
                            if cached_saml_request and cached_binding:
                                saml_request = cached_saml_request
                                binding = cached_binding
                                relay_state = cached_relay_state
                                logger.info(
                                    f"SAML2 Login Process: Retrieved from session-key-based cache fallback (backward compatibility). "
                                    f"Cache key: {cache_key}, "
                                    f"Binding: {binding}"
                                )
                                # Restore to session
                                try:
                                    request.session['SAMLRequest'] = saml_request
                                    request.session['Binding'] = binding
                                    request.session['RelayState'] = relay_state
                                    request.session.save()
                                    logger.debug("SAML2 Login Process: Restored session-key-based cache data to session")
                                except Exception as restore_error:
                                    logger.warning(f"SAML2 Login Process: Failed to restore cache data to session: {restore_error}")
                            else:
                                logger.error(
                                    f"SAML2 Login Process: Session-key-based cache data incomplete. "
                                    f"Cache key: {cache_key}"
                                )
                        else:
                            logger.error(
                                f"SAML2 Login Process: All cache fallbacks failed. "
                                f"Session-key cache key: {cache_key} not found. "
                                f"This indicates session was lost between SSO entry and login process."
                            )
                    except Exception as cache_error:
                        logger.error(f"SAML2 Login Process: Session-key-based cache fallback error: {cache_error}")
            
            # If still no SAMLRequest, raise user-friendly error
            if not saml_request:
                error_msg = (
                    "SAML2 authentication request data was lost. This can happen if:\n"
                    "- Your browser blocks third-party cookies\n"
                    "- Session cookies expired between redirects\n"
                    "- Browser security settings are too strict\n\n"
                    "Please try again. If the problem persists, check your browser's cookie settings."
                )
                logger.error(
                    f"SAML2 Login Process: Cannot proceed - no SAMLRequest found. "
                    f"Session: {request.session.session_key}, "
                    f"Session keys: {list(request.session.keys())}"
                )
                return error_cbv.handle_error(
                    request, 
                    exception=ValidationError(error_msg), 
                    status_code=400
                )

        # TODO: would it be better to store SAML info in request objects?
        # AuthBackend takes request obj as argument...
        try:
            idp_server = IDP.load()

            # Parse incoming request
            req_info = idp_server.parse_authn_request(saml_request, binding)

            # check SAML request signature
            try:
                verify_request_signature(req_info)
            except ValueError as excp:
                return error_cbv.handle_error(request, exception=excp, status_code=400)

            # Compile Response Arguments
            resp_args = idp_server.response_args(req_info.message)
            # Set SP and Processor
            sp_entity_id = resp_args.pop('sp_entity_id')
            service_provider = get_sp_config(sp_entity_id)
            # Check if user has access
            try:
                # Check if user has access to SP
                check_access(service_provider.processor, request)
            except PermissionDenied as excp:
                return error_cbv.handle_error(request, exception=excp, status_code=403)
            # Construct SamlResponse message
            authn_resp = build_authn_response(request.user, get_authn(), resp_args, service_provider)
        except Exception as e:
            return error_cbv.handle_error(request, exception=e, status_code=500)

        # Validate binding consistency: cached binding (used for parsing) vs response binding (authoritative)
        # The response binding comes from SAML response and is authoritative, but we log for debugging
        response_binding = resp_args['binding']
        if binding != response_binding:
            logger.debug(
                f"SAML2 Login Process: Binding mismatch detected. "
                f"Cached/parsed binding: {binding}, Response binding: {response_binding}. "
                f"Using response binding (authoritative)."
            )
        else:
            logger.debug(
                f"SAML2 Login Process: Binding consistency verified. "
                f"Both cached and response binding: {response_binding}"
            )

        html_response = self.create_html_response(
            request,
            binding=response_binding,  # Use response binding (authoritative from SAML response)
            authn_resp=authn_resp,
            destination=resp_args['destination'],
            relay_state=relay_state)

        logger.debug("--- SAML Authn Response [\n{}] ---".format(repr_saml(str(authn_resp))))
        return self.render_response(request, html_response, service_provider.processor)


@method_decorator(never_cache, name='dispatch')
class SSOInitView(LoginRequiredMixin, IdPHandlerViewMixin, View):
    """ View used for IDP initialized login, doesn't handle any SAML authn request
    """

    def post(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        return self.get(request, *args, **kwargs)

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        request_data = request.POST or request.GET
        passed_data: Dict[str, Union[str, List[str]]] = request_data.copy().dict()

        try:
            # get sp information from the parameters
            sp_entity_id = str(passed_data['sp'])
            service_provider = get_sp_config(sp_entity_id)
            processor: BaseProcessor = service_provider.processor  # type: ignore
        except (KeyError, ImproperlyConfigured) as excp:
            return error_cbv.handle_error(request, exception=excp, status_code=400)

        try:
            # Check if user has access to SP
            check_access(processor, request)
        except PermissionDenied as excp:
            return error_cbv.handle_error(request, exception=excp, status_code=403)

        idp_server = IDP.load()

        binding_out, destination = idp_server.pick_binding(
            service="assertion_consumer_service",
            entity_id=sp_entity_id)

        # Adding a few things that would have been added if this were SP Initiated
        passed_data['destination'] = destination
        passed_data['in_response_to'] = "IdP_Initiated_Login"

        # Construct SamlResponse messages
        authn_resp = build_authn_response(request.user, get_authn(), passed_data, service_provider)

        html_response = self.create_html_response(request, binding_out, authn_resp, destination, passed_data.get('RelayState', ""))
        return self.render_response(request, html_response, processor)


@method_decorator(never_cache, name='dispatch')
class ProcessMultiFactorView(LoginRequiredMixin, View):
    """ This view is used in an optional step is to perform 'other' user validation, for example 2nd factor checks.
        Override this view per the documentation if using this functionality to plug in your custom validation logic.
    """

    def multifactor_is_valid(self, request: HttpRequest) -> bool:
        """ The code here can do whatever it needs to validate your user (via request.user or elsewise).
            It must return True for authentication to be considered a success.
        """
        return True

    def get(self, request: HttpRequest, *args, **kwargs):
        if self.multifactor_is_valid(request):
            logger.debug('MultiFactor succeeded for %s' % request.user)
            html_response = request.session['saml_data']
            if html_response['type'] == 'POST':
                return HttpResponse(html_response['data'])
            else:
                return HttpResponseRedirect(html_response['data'])
        logger.debug(_("MultiFactor failed; %s will not be able to log in") % request.user)
        logout(request)
        raise PermissionDenied(_("MultiFactor authentication factor failed"))


@method_decorator([never_cache, csrf_exempt], name='dispatch')
class LogoutProcessView(LoginRequiredMixin, IdPHandlerViewMixin, View):
    """ View which processes the actual SAML Single Logout request
        The login_required decorator ensures the user authenticates first on the IdP using 'normal' way.
    """
    __service_name = 'Single LogOut'

    def post(self, request: HttpRequest, *args, **kwargs):
        return self.get(request, *args, **kwargs)

    def get(self, request: HttpRequest, *args, **kwargs):
        logger.info("--- {} Service ---".format(self.__service_name))
        # do not assign a variable that overwrite request object, if it will fail the return with HttpResponseBadRequest trows naturally
        store_params_in_session(request)
        binding = request.session['Binding']
        relay_state = request.session['RelayState']
        logger.debug("--- {} requested [\n{}] to IDP ---".format(self.__service_name, binding))

        idp_server = IDP.load()

        # adapted from pysaml2 examples/idp2/idp_uwsgi.py
        try:
            req_info = idp_server.parse_logout_request(request.session['SAMLRequest'], binding)
        except Exception as excp:
            expc_msg = "{} Bad request: {}".format(self.__service_name, excp)
            logger.error(expc_msg)
            return error_cbv.handle_error(request, exception=expc_msg, status_code=400)

        logger.debug("{} - local identifier: {} from {}".format(self.__service_name, req_info.message.name_id.text, req_info.message.name_id.sp_name_qualifier))
        logger.debug("--- {} SAML request [\n{}] ---".format(self.__service_name, repr_saml(req_info.xmlstr, b64=False)))

        # TODO
        # check SAML request signature
        try:
            verify_request_signature(req_info)
        except ValueError as excp:
            return error_cbv.handle_error(request, exception=excp, status_code=400)

        resp = idp_server.create_logout_response(req_info.message, [binding])

        '''
        # TODO: SOAP
        # if binding == BINDING_SOAP:
            # destination = ""
            # response = False
        # else:
            # binding, destination = IDP.pick_binding(
                # "single_logout_service", [binding], "spsso", req_info
            # )
            # response = True
        # END TODO SOAP'''

        try:
            # hinfo returns request or response, it depends by request arg
            hinfo = idp_server.apply_binding(binding, resp.__str__(), resp.destination, relay_state, response=True)
        except Exception as excp:
            logger.error("ServiceError: %s", excp)
            return error_cbv.handle_error(request, exception=excp, status=400)

        logger.debug("--- {} Response [\n{}] ---".format(self.__service_name, repr_saml(resp.__str__().encode())))
        logger.debug("--- binding: {} destination:{} relay_state:{} ---".format(binding, resp.destination, relay_state))

        # TODO: double check username session and saml login request
        # logout user from IDP
        logout(request)

        if hinfo['method'] == 'GET':
            return HttpResponseRedirect(hinfo['headers'][0][1])
        else:
            html_response = self.create_html_response(
                request,
                binding=binding,
                authn_resp=resp.__str__(),
                destination=resp.destination,
                relay_state=relay_state)
        return self.render_response(request, html_response, None)


@never_cache
def get_multifactor(request: HttpRequest) -> HttpResponse:
    if hasattr(settings, "SAML_IDP_MULTIFACTOR_VIEW"):
        multifactor_class = import_string(getattr(settings, "SAML_IDP_MULTIFACTOR_VIEW"))
    else:
        multifactor_class = ProcessMultiFactorView
    return multifactor_class.as_view()(request)


@never_cache
def metadata(request: HttpRequest) -> HttpResponse:
    """ Returns an XML with the SAML 2.0 metadata for this Idp.
        The metadata is constructed on-the-fly based on the config dict in the django settings.
    """
    return HttpResponse(content=IDP.metadata().encode('utf-8'), content_type="text/xml; charset=utf8")
