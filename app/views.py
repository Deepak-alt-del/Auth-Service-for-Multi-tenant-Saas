from rest_framework import status, permissions
from rest_framework.response import Response
from django.db.models import Count
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken ,AccessToken
from django.contrib.auth.hashers import check_password, make_password
from .models import User, Organization, Member, Role
from .serializers import UserSerializer, OrganizationSerializer, MemberSerializer, RoleSerializer
from django.utils import timezone
from django.conf import settings
from datetime import datetime
import resend



def generate_email(to_mail, subject, content):
    '''
        Used the resend API to send emails in different scenarios
    '''
    resend.api_key = settings.RESEND_API_KEY

    params: resend.Emails.SendParams = {
      "from": "test123@resend.dev",
      "to": to_mail,
      "subject": subject,
      "html": content
        }
    email: resend.Email = resend.Emails.send(params)



@api_view(['POST'])
def sign_up(request):
    '''
        Creates a database user and sends an email to the appropriate user for verification
    '''
    FRONTEND_URL = settings.FRONTEND_URL
    user_serializer = UserSerializer(data=request.data)
    
    if user_serializer.is_valid():
        user = user_serializer.save(password=make_password(request.data['password']), status=0)
        refresh = RefreshToken.for_user(user)
        confirmation_link = f"{FRONTEND_URL}/confirm-email/{refresh.access_token}/"
        generate_email(user.email, "Sign-Up Confirmation", f'<a href="{confirmation_link}">Confirm your email</a>')
        return Response({'message': 'User created successfully. Please verify your email to complete the registration.','link':confirmation_link}, status=status.HTTP_201_CREATED)
    
    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def sign_up_email_verification(request, token):
    '''
        Received an email after sign-up; 
        needs verification through a JWT token
    '''
    try:
        access_token = AccessToken(token)
        user = User.objects.get(id=access_token['user_id'])
        
        if user.status == '1':
            return Response({'message': 'Account already activated'}, status=status.HTTP_400_BAD_REQUEST)
        
        user.status = 1
        user.save()
        return Response({'message': 'Account activated successfully'}, status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def sign_in(request):
    '''
        After verifying the user via email, they can log in.
        The logged-in user will receive a JWT token for further authorization processes 
    '''
    email = request.data.get('email')
    password = request.data.get('password')
    try:
        user = User.objects.get(email=email)
        if user.status == 0 :
            return Response({"Confirm-Mail":"Please confirm your mail before Log-In attempt"},status=status.HTTP_401_UNAUTHORIZED)  
        else:
            if check_password(password, user.password):

                formatted_login_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                email_content = f'''
                <p>Dear {username},</p>
                <p>We detected a login attempt to your account.</p>
                <p><strong>Login Time:</strong> {formatted_login_time}</p>
                <p>If this was not you, please secure your account immediately.</p>
                <p>Best regards,<br>Your Company</p>
                '''

                generate_email(user.email, "Login Attempt Detected", email_content)
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })

        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)



@api_view(['GET'])
def roles_without_members(request):
    FRONTEND_URL = settings.FRONTEND_URL
    '''
        GET request to retrieve all roles within the organization.
        An authorized user can become a member by clicking on the link
    '''
    roles_with_no_members = Role.objects.exclude(id__in=Member.objects.values('role'))
    
    response_data = []
    for role in roles_with_no_members:
        role_data = {
            'name': role.name,
            'organization_name': role.org.name,
            'confirmation_link': f"{FRONTEND_URL}/confirm/{role.id}/"
        }
        response_data.append(role_data)
    
    return Response(response_data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def create_acc_from_link(request, id):
    '''
     By clicking on the open roles, user become part of the member.
    '''
    # Ensure the user is authenticated
    if not request.user.is_authenticated:
        return Response({'error': 'User not authenticated.'}, status=status.HTTP_403_FORBIDDEN)

    # Fetch the role or return 404 if not found
    role = get_object_or_404(Role, id=id)
    
    # Create a Member record linking the role with the organization and user
    Member.objects.create(org=role.org, user=request.user, role=role)
    
    return Response({'success': 'Account created and role assigned.'}, status=status.HTTP_201_CREATED)



@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def logout(request):
    '''
        login user can logout.
        done by destoying JWT refresh token.
    '''
    refresh_token = request.data.get('refresh')
    print(refresh_token)
    if refresh_token:
        try:
            token = RefreshToken(refresh_token)
            # Blacklist the refresh token
            token.blacklist()
            return Response({'message': 'Successfully logged out'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    return Response({'error': 'No refresh token provided'}, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
def reset_password(request):
    """
    Handles the password reset request. Generates a password reset link
    and sends it to the user's email.
    """
    FRONTEND_URL = settings.FRONTEND_URL
    email = request.data.get('email')
    
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
        refresh = RefreshToken.for_user(user)
        pass_reset_link = f"{FRONTEND_URL}/reset-password/{refresh.access_token}/"

        email_content = f'''
        <p>We received a request to reset your password. Click the link below to set a new password:</p>
        <p><a href="{pass_reset_link}">Reset your password</a></p>
        <p>If you did not request a password reset, please ignore this email.</p>
        '''

        generate_email(user.email, "Password Reset Link", email_content)
        
        return Response({'message': 'Password reset link has been sent to your email. Please check your inbox.'}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
def reset_password_from_mail(request, token):
    """
    Resets the user's password based on the provided JWT token.
    """
    new_password = request.data.get('password')
    confirm_password = request.data.get('confirm_password')

    if new_password != confirm_password:
        return Response({"error": "New password and confirm password do not match"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        access_token = AccessToken(token)
        user_id = access_token['user_id']
        user = get_object_or_404(User, id=user_id)
        
        user.set_password(new_password)  # Hash and set the new password
        user.save()
        
        return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)




# @api_view(['POST'])
# @permission_classes([permissions.IsAuthenticated])
# def invite_member(request):
#     data = request.data
#     org_id = data.get('org_id')
#     user_email = data.get('user_email')
#     role_id = data.get('role_id')
#     try:
#         user = User.objects.get(email=user_email)
#         org = Organization.objects.get(id=org_id)
#         role = Role.objects.get(id=role_id)
#         Member.objects.create(org=org, user=user, role=role)
#         return Response({'message': 'Member invited successfully'}, status=status.HTTP_200_OK)
#     except (User.DoesNotExist, Organization.DoesNotExist, Role.DoesNotExist):
#         return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated])
def delete_member(request):
    '''
        Handled the deletion of a member
    '''
    data = request.data
    role_id = data.get('role_id')
    user_email = data.get('user_email')
    try:
        user = User.objects.get(email=user_email)
        role = Role.objects.get(id=role_id)
        org = role.org
        member = Member.objects.get(org=org, user=user , role=role)
        member.delete()
        return Response({'message': 'Member deleted successfully'}, status=status.HTTP_200_OK)
    except (User.DoesNotExist, Organization.DoesNotExist, Member.DoesNotExist):
        return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@permission_classes([permissions.IsAuthenticated])
def update_member_role(request):
    '''
        Can update member role with new organisation.
    '''
    data = request.data
    user_email = data.get('user_email')
    old_role_id = data.get('old_role_id')
    new_role_id = data.get('new_role_id')
    # org_id = data.get('org_id')
    try:
        user = User.objects.get(email=user_email)
        old_role = Role.objects.get(id=old_role_id)
        old_org = old_role.org
        member = Member.objects.get(org=old_org, user=user , role=old_role)
        
        new_role = Role.objects.get(id=new_role_id)
        new_org = new_role.org

        member.role = new_role
        member.org = new_org
        member.save()
        return Response({'message': 'Member role updated successfully'}, status=status.HTTP_200_OK)
    except (User.DoesNotExist, Organization.DoesNotExist, Role.DoesNotExist, Member.DoesNotExist):
        return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)







@api_view(['GET'])
def role_wise_user_count(request):
    """
    API for counting users per role.
    """
    try:
        roles = Role.objects.annotate(user_count=Count('member')).values('name', 'user_count')
        return Response(list(roles), status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def organization_wise_member_count(request):
    """
        API for counting members per organization with optional filters.
        
    """
    # Parse filters from request
    from_time_str = request.GET.get('from_time')
    to_time_str = request.GET.get('to_time')
    status_filter = request.GET.get('status')
    
    
    from_time = None
    to_time = None
    
    if from_time_str:
        from_time = parse_datetime(from_time_str)
        if from_time is None:
            return Response({'error': 'Invalid from_time format. Use ISO 8601 format.'}, status=status.HTTP_400_BAD_REQUEST)
        from_time = int(from_time.timestamp())
    
    if to_time_str:
        to_time = parse_datetime(to_time_str)
        if to_time is None:
            return Response({'error': 'Invalid to_time format. Use ISO 8601 format.'}, status=status.HTTP_400_BAD_REQUEST)
        to_time = int(to_time.timestamp())
    
    
    query = Member.objects.values('org__name').annotate(member_count=Count('id'))
    
    if from_time is not None:
        query = query.filter(created_at__gte=from_time)
    if to_time is not None:
        query = query.filter(created_at__lte=to_time)
    if status_filter:
        query = query.filter(status=status_filter)
    
    result = list(query)
    return Response(result, status=status.HTTP_200_OK)

@api_view(['GET'])
def organization_role_wise_user_count(request):
    """
    API for counting users by role within each organization with optional filters.
    """
    
    from_time_str = request.GET.get('from_time')
    to_time_str = request.GET.get('to_time')
    status_filter = request.GET.get('status')
    
    
    from_time = None
    to_time = None
    
    if from_time_str:
        from_time = parse_datetime(from_time_str)
        if from_time is None:
            return Response({'error': 'Invalid from_time format. Use ISO 8601 format.'}, status=status.HTTP_400_BAD_REQUEST)
        from_time = int(from_time.timestamp())
    
    if to_time_str:
        to_time = parse_datetime(to_time_str)
        if to_time is None:
            return Response({'error': 'Invalid to_time format. Use ISO 8601 format.'}, status=status.HTTP_400_BAD_REQUEST)
        to_time = int(to_time.timestamp())
    
    # Build the query
    query = (Member.objects
             .values('org__name', 'role__name')
             .annotate(user_count=Count('user_id'))
             .order_by('org__name', 'role__name'))
    
    if from_time is not None:
        query = query.filter(created_at__gte=from_time)
    if to_time is not None:
        query = query.filter(created_at__lte=to_time)
    if status_filter:
        query = query.filter(status=status_filter)
    
    result = list(query)
    return Response(result, status=status.HTTP_200_OK)






@api_view(['POST'])
def add_owner_member(request):
    '''
        created user from mail and password.
        created organisation with role.
        created member of organisation as role "owner"(true)

    '''
    userdata = {
        'email': request.data.get('email'),
        'password': request.data.get('password'),
    }

    # Create the user
    user_serializer = UserSerializer(data=userdata)
    if user_serializer.is_valid():
        user = user_serializer.save(password=make_password(userdata['password']))
        
        # Create the organization
        org_name = request.data.get('organization_name')
        if not org_name:
            return Response({'error': 'Organization name is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        org = Organization.objects.create(name=org_name, personal=True)
        
        # Create the role
        role_name = request.data.get('role_name')
        if not role_name:
            return Response({'error': 'Role name is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        role = Role.objects.create(name=role_name, org=org)
        
        # Create the membership
        try:
            Member.objects.create(org=org, user=user, role=role)
            return Response({'message': 'User created and added as owner successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)




