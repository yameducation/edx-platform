"""Organizations views for use with Studio."""


from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.generic import View
from organizations.api import get_organizations

from openedx.core.djangolib.js_utils import dump_js_escaped_json


class OrganizationListView(View):
    """View rendering organization list as json.

    This view renders organization list json which is used in org
    autocomplete while creating new course.
    """

    @method_decorator(login_required)
    def get(self, request, *args, **kwargs):  # lint-amnesty, pylint: disable=unused-argument
        """Returns organization list as json."""
        if request:
            host = request.get_host().split(':')[0]
        else:
        # fallback (e.g. background tasks)
            host = settings.SITE_NAME  

        normalized_host = host.replace("studio.", "", 1) if host.startswith("studio.") else host

        logging.info(f"[Tenant Orgs] Normalized host: {normalized_host}")

        organizations = get_organizations()
        logging.info(f'organizationsssssssssssssssss {organizations}')
        org_names_list = [(org["short_name"]) for org in organizations]


        try:
            tenant_config = TenantConfig.objects.get_configurations(domain=normalized_host)
            allowed_orgs = cd _config.get("lms_configs", {}).get("course_org_filter", [])
            logging.info(f"[Tenant Orgs] Allowed orgs for {normalized_host}: {allowed_orgs}")

            if allowed_orgs:
            # filter only allowed orgs
                organizations = [org for org in organizations if org["short_name"] in allowed_orgs]
                org_names_list = [org["short_name"] for org in organizations]
        except TenantConfig.DoesNotExist:
            logging.warning(f"[Tenant Orgs] Tenant config not found for {normalized_host}, returning all orgs")

        return HttpResponse(dump_js_escaped_json(org_names_list), content_type='application/json; charset=utf-8')  
