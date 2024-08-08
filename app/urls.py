from django.urls import path
from . import views

urlpatterns = [
    path('sign-up/', views.sign_up, name='sign_up'),
    path('logout/', views.logout, name='logout'),
    path('sign-in/', views.sign_in, name='sign_in'),
    path('reset-password/', views.reset_password, name='reset_password'),
    # path('invite-member/', views.invite_member, name='invite_member'),
    path('delete-member/', views.delete_member, name='delete_member'),
    path('update-member-role/', views.update_member_role, name='update_member_role'),
    path('add-owner-member/', views.add_owner_member, name='add_owner_member'),
    path('roles-without-members/', views.roles_without_members, name='roles_without_members'),
    path('confirm/<int:id>/', views.create_acc_from_link, name='create_acc_from_link'),
    path('confirm-email/<str:token>/', views.sign_up_email_verification, name='sign_up_email_verification'),
    path('reset-password/<str:token>/', views.reset_password_from_mail, name='reset-password-from-mail'),

]


urlpatterns += [
    path('api/role-wise-user-count/', views.role_wise_user_count, name='role-wise-user-count'),
    path('api/organization-wise-member-count/', views.organization_wise_member_count, name='organization-wise-member-count'),
    path('api/organization-role-wise-user-count/', views.organization_role_wise_user_count, name='organization-role-wise-user-count'),
]