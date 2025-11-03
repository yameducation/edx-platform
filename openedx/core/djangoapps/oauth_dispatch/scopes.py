"""
Custom Django OAuth Toolkit scopes backends.
"""


from oauth2_provider.scopes import SettingsScopes

from openedx.core.djangoapps.oauth_dispatch.models import ApplicationAccess

import logging

class ApplicationModelScopes(SettingsScopes):
    """
    Scopes backend that determines available scopes using the ApplicationAccess model.
    """
    def get_available_scopes(self, application=None, request=None, *args, **kwargs):  # lint-amnesty, pylint: disable=keyword-arg-before-vararg
        """ Returns valid scopes configured for the given application. """
        try:
            application_scopes = ApplicationAccess.get_scopes(application)
            if 'user_id' not in application_scopes:
                application_scopes.append('user_id')
            logging.info(f'application scopes are like this {application_scopes}')
            

        except ApplicationAccess.DoesNotExist:
            application_scopes = []

        default_scopes = self.get_default_scopes()
        logging.info(f'set of application scope + default _scope {set(application_scopes + default_scopes)}')
        all_scopes = list(self.get_all_scopes().keys())
        logging.info(f'all_scopes {all_scopes}')
        return set(application_scopes + default_scopes).intersection(all_scopes)
