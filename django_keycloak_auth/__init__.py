"""
███╗   ██╗███████╗██╗  ██╗████████╗    ██╗    ██╗███████╗███████╗██╗  ██╗    ██╗    ██╗██╗████████╗██╗  ██╗    ██╗   ██╗███████╗
████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝    ██║    ██║██╔════╝██╔════╝██║ ██╔╝    ██║    ██║██║╚══██╔══╝██║  ██║    ██║   ██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝    ██║       ██║ █╗ ██║█████╗  █████╗  █████╔╝     ██║ █╗ ██║██║   ██║   ███████║    ██║   ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗    ██║       ██║███╗██║██╔══╝  ██╔══╝  ██╔═██╗     ██║███╗██║██║   ██║   ██╔══██║    ██║   ██║╚════██║
██║ ╚████║███████╗██╔╝ ██╗   ██║       ╚███╔███╔╝███████╗███████╗██║  ██╗    ╚███╔███╔╝██║   ██║   ██║  ██║    ╚██████╔╝███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝        ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝     ╚═════╝ ╚══════╝
                                                                                                                                
"""
from django.conf import settings
import warnings

__title__ = 'Django Keycloak Auth'
__version__ = '0.1.13'
__author__ = 'Ehsan Ahmadi'
__license__ = 'BSD 3-Clause'
__copyright__ = 'Copyright 2024-2025 Encode OSS Ltd'

# Version synonym
VERSION = __version__

# Header encoding (see RFC5987)
HTTP_HEADER_ENCODING = 'iso-8859-1'

# Default datetime input and output formats
ISO_8601 = 'iso-8601'


class RemovedInDRF317Warning(PendingDeprecationWarning):
    pass

if hasattr(settings, 'INSTALLED_APPS'):
    if 'django_keycloak_auth' not in getattr(settings, 'INSTALLED_APPS', []):
           warnings.warn(
                "\n\n\n⚠️ You must add 'django_keycloak_auth' to INSTALLED_APPS in your Django settings.\n\n\n",
                UserWarning,
            )