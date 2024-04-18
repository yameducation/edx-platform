"""
Celery tasks for sending email notifications
"""
from celery import shared_task
from edx_ace import ace
from edx_ace.recipient import Recipient
from edx_django_utils.monitoring import set_code_owner_attribute

from openedx.core.djangoapps.notifications.email_notifications import EmailCadence
from openedx.core.djangoapps.notifications.models import (
    CourseNotificationPreference,
    Notification,
    get_course_notification_preference_config_version
)
from .message_type import EmailNotificationMessageType
from .utils import (
    create_app_notifications_dict,
    create_email_digest_context,
    filter_notification_with_email_enabled_preferences,
    get_start_end_date,
    get_unique_course_ids,
    is_email_notification_flag_enabled
)


def get_audience_for_cadence_email(cadence_type):
    """
    Returns users that are eligible to receive cadence email
    """
    if cadence_type not in [EmailCadence.DAILY, EmailCadence.WEEKLY]:
        raise ValueError("Invalid value for parameter cadence_type")
    start_date, end_date = get_start_end_date(cadence_type)
    users = Notification.objects.filter(
        email=True,
        created__gte=start_date,
        created__lte=end_date
    ).values_list('user__username', flat=True).distinct()
    return users


def get_user_preferences_for_courses(course_ids, user):
    """
    Returns updated user preference for course_ids
    """
    # Create new preferences
    new_preferences = []
    preferences = CourseNotificationPreference.objects.filter(user=user, course_id__in=course_ids)
    preferences = list(preferences)
    for course_id in course_ids:
        if not any(preference.course_id == course_id for preference in preferences):
            pref = CourseNotificationPreference(user=user, course_id=course_id)
            new_preferences.append(pref)
    if new_preferences:
        CourseNotificationPreference.objects.bulk_create(new_preferences, ignore_conflicts=True)
    # Update preferences to latest config version
    current_version = get_course_notification_preference_config_version()
    for preference in preferences:
        if preference.config_version != current_version:
            preference = preference.get_user_course_preference(user.id, preference.course_id)
        new_preferences.append(preference)
    return new_preferences


def send_digest_email_to_user(user, cadence_type, course_language='en', courses_data=None):
    """
    Send [cadence_type] email to user.
    Cadence Type can be EmailCadence.DAILY or EmailCadence.WEEKLY
    """
    if cadence_type not in [EmailCadence.DAILY, EmailCadence.WEEKLY]:
        raise ValueError('Invalid cadence_type')
    if not is_email_notification_flag_enabled(user):
        return
    start_date, end_date = get_start_end_date(cadence_type)
    notifications = Notification.objects.filter(user=user, email=True,
                                                created__gte=start_date, created__lte=end_date)
    if not notifications:
        return
    course_ids = get_unique_course_ids(notifications)
    preferences = get_user_preferences_for_courses(course_ids, user)
    notifications = filter_notification_with_email_enabled_preferences(notifications, preferences, cadence_type)
    if not notifications:
        return
    apps_dict = create_app_notifications_dict(notifications)
    message_context = create_email_digest_context(apps_dict, start_date, end_date, cadence_type,
                                                  courses_data=courses_data)
    recipient = Recipient(user.id, user.email)
    message = EmailNotificationMessageType(
        app_label="notifications", name="email_digest"
    ).personalize(recipient, course_language, message_context)
    ace.send(message)


@shared_task(ignore_result=True)
@set_code_owner_attribute
def send_digest_email_to_all_users(cadence_type):
    """
    Send email digest to all eligible users
    """
    users = get_audience_for_cadence_email(cadence_type)
    courses_data = {}
    for user in users:
        send_digest_email_to_user(user, cadence_type, courses_data=courses_data)
