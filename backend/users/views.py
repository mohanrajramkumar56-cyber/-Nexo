from django.contrib.auth import get_user_model
from rest_framework import generics, permissions, status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import EmailVerificationCode, Notification
from .serializers import (
    NotificationSerializer,
    RegisterSerializer,
    UserSerializer,
    UserWithProjectsSerializer,
)
from .utils import generate_otp_code, send_verification_email, validate_password_strength

User = get_user_model()


class RegisterView(generics.CreateAPIView):
    """POST username/email/password -> creates inactive user + dispatches 6-digit OTP email."""
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response(
            {
                "require_verification": True,
                "email": user.email,
                "detail": f"A 6-digit verification code has been sent to {user.email}.",
            },
            status=status.HTTP_201_CREATED,
        )



class VerifyCodeView(APIView):
    """
    POST email, code, purpose ('REGISTRATION' or 'PASSWORD_RESET')
    Validates 6-digit OTP code and activates user account if purpose is REGISTRATION.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email", "").strip().lower()
        code = request.data.get("code", "").strip()
        purpose = request.data.get("purpose", "REGISTRATION").strip().upper()

        if not email or not code:
            return Response(
                {"detail": "Email address and 6-digit verification code are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Lookup matching verification code
        v_code = (
            EmailVerificationCode.objects.filter(
                email__iexact=email,
                code=code,
                purpose=purpose,
                is_used=False,
            )
            .order_by("-created_at")
            .first()
        )

        if not v_code or not v_code.is_valid(expiration_minutes=15):
            return Response(
                {"detail": "Invalid or expired verification code. Please check or request a new code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if purpose == "REGISTRATION":
            # Activate user account
            user = User.objects.filter(email__iexact=email).first()
            if not user:
                return Response({"detail": "User account not found."}, status=status.HTTP_404_NOT_FOUND)

            user.is_active = True
            user.save()
            v_code.is_used = True
            v_code.save()

            token, _ = Token.objects.get_or_create(user=user)
            return Response(
                {
                    "verified": True,
                    "token": token.key,
                    "user": UserSerializer(user).data,
                    "detail": "Email successfully verified! Welcome to NEXO Software.",
                },
                status=status.HTTP_200_OK,
            )

        elif purpose == "PASSWORD_RESET":
            return Response(
                {
                    "verified": True,
                    "detail": "Code verified. You may now enter your new password.",
                },
                status=status.HTTP_200_OK,
            )

        return Response({"detail": "Unsupported purpose."}, status=status.HTTP_400_BAD_REQUEST)


class ResendCodeView(APIView):
    """POST email, purpose -> generates fresh 6-digit OTP code and dispatches email."""
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email", "").strip().lower()
        purpose = request.data.get("purpose", "REGISTRATION").strip().upper()

        if not email:
            return Response({"detail": "Email address is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email__iexact=email).first()
        if not user and purpose == "REGISTRATION":
            return Response({"detail": "No registration found for this email."}, status=status.HTTP_404_NOT_FOUND)
        if not user and purpose == "PASSWORD_RESET":
            return Response({"detail": "No account found with this email."}, status=status.HTTP_404_NOT_FOUND)

        # Invalidate old unused codes
        EmailVerificationCode.objects.filter(email__iexact=email, purpose=purpose, is_used=False).update(is_used=True)

        # Generate fresh code
        code = generate_otp_code(6)
        EmailVerificationCode.objects.create(
            email=email,
            user=user,
            code=code,
            purpose=purpose,
        )
        email_sent = send_verification_email(
            email=email,
            code=code,
            purpose=purpose,
            username=user.username if user else "",
        )

        if not email_sent:
            EmailVerificationCode.objects.filter(
                email__iexact=email,
                code=code,
                purpose=purpose,
                is_used=False,
            ).delete()
            return Response(
                {
                    "detail": email_sent.reason
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response(
            {
                "success": True,
                "detail": f"A new verification code has been dispatched to {email}.",
            },
            status=status.HTTP_200_OK,
        )


class LoginView(ObtainAuthToken):
    """POST email/password -> checks active status & returns auth token + basic user info."""
    def post(self, request, *args, **kwargs):
        email_input = request.data.get("username", "").strip().lower()  # field is named 'username' for DRF compat
        password = request.data.get("password", "").strip()

        if not email_input or not password:
            return Response(
                {"detail": "Email and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Look up user by email
        user = (
            User.objects.filter(email__iexact=email_input).first()
            or User.objects.filter(username__iexact=email_input).first()
        )

        if not user:
            return Response(
                {"detail": "No account found with this email. Please check your credentials."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if user is inactive (unverified email) — just activate and log in directly
        if not user.is_active:
            user.is_active = True
            user.save()

        # Verify password
        if not user.check_password(password):
            return Response(
                {"detail": "Incorrect password. Please try again."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token, _ = Token.objects.get_or_create(user=user)
        return Response({"token": token.key, "user": UserSerializer(user).data})


class VerifyEmailView(APIView):
    """POST email -> verifies email exists in DB and dispatches a 6-digit password reset OTP."""
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email_or_username = request.data.get("email", "").strip()
        if not email_or_username:
            return Response(
                {"detail": "Please enter your email or username."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = (
            User.objects.filter(email__iexact=email_or_username).first()
            or User.objects.filter(username__iexact=email_or_username).first()
        )

        if not user:
            return Response(
                {"detail": "No account found matching this email or username."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Invalidate old unused reset codes
        EmailVerificationCode.objects.filter(
            email__iexact=user.email,
            purpose="PASSWORD_RESET",
            is_used=False,
        ).update(is_used=True)

        # Generate fresh reset code
        code = generate_otp_code(6)
        EmailVerificationCode.objects.create(
            email=user.email,
            user=user,
            code=code,
            purpose="PASSWORD_RESET",
        )
        email_sent = send_verification_email(
            email=user.email,
            code=code,
            purpose="PASSWORD_RESET",
            username=user.username,
        )

        if not email_sent:
            EmailVerificationCode.objects.filter(
                email__iexact=user.email,
                code=code,
                purpose="PASSWORD_RESET",
                is_used=False,
            ).delete()
            return Response(
                {"detail": email_sent.reason},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response(
            {
                "exists": True,
                "username": user.username,
                "email": user.email,
                "detail": f"A 6-digit password reset code has been sent to {user.email}.",
            },
            status=status.HTTP_200_OK,
        )



class ResetPasswordView(APIView):
    """POST email, code, new_password -> verifies OTP code and updates user password."""
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email_or_username = request.data.get("email", "").strip()
        code = request.data.get("code", "").strip()
        new_password = request.data.get("new_password", "").strip()

        if not email_or_username or not code or not new_password:
            return Response(
                {"detail": "Email, 6-digit verification code, and new password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        is_valid_pwd, pwd_err = validate_password_strength(new_password)
        if not is_valid_pwd:
            return Response(
                {"detail": pwd_err},
                status=status.HTTP_400_BAD_REQUEST,
            )


        user = (
            User.objects.filter(email__iexact=email_or_username).first()
            or User.objects.filter(username__iexact=email_or_username).first()
        )

        if not user:
            return Response(
                {"detail": "No account found with this email or username."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Validate 6-digit OTP code
        v_code = (
            EmailVerificationCode.objects.filter(
                email__iexact=user.email,
                code=code,
                purpose="PASSWORD_RESET",
                is_used=False,
            )
            .order_by("-created_at")
            .first()
        )

        if not v_code or not v_code.is_valid(expiration_minutes=15):
            return Response(
                {"detail": "Invalid or expired verification code. Please check your email or request a new code."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new_password)
        user.save()

        # Invalidate code & old auth tokens
        v_code.is_used = True
        v_code.save()
        Token.objects.filter(user=user).delete()
        token = Token.objects.create(user=user)

        return Response(
            {
                "success": True,
                "username": user.username,
                "token": token.key,
                "detail": "Password has been successfully updated. You may now log in.",
            },
            status=status.HTTP_200_OK,
        )


class MeView(generics.RetrieveUpdateAPIView):
    """GET / PATCH current logged-in user."""
    serializer_class = UserSerializer

    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class UserListView(generics.ListAPIView):
    """GET /api/auth/users/?search= -> search/list all users for teams directory, assignment and member invites."""
    serializer_class = UserWithProjectsSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = User.objects.all().order_by("username")
        query = self.request.query_params.get("search", "").strip()
        if query:
            qs = qs.filter(username__icontains=query) | qs.filter(email__icontains=query)
        return qs


class NotificationViewSet(viewsets.ModelViewSet):
    """CRUD API for user notifications."""
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(recipient=self.request.user)

    def perform_create(self, serializer):
        serializer.save(actor=self.request.user)

    @action(detail=False, methods=["post"])
    def mark_all_read(self, request):
        Notification.objects.filter(recipient=request.user, read=False).update(read=True)
        return Response({"status": "all marked as read"})

    @action(detail=False, methods=["delete"])
    def clear_all(self, request):
        Notification.objects.filter(recipient=request.user).delete()
        return Response({"status": "cleared all"})


class DashboardView(APIView):
    """
    GET /api/auth/dashboard/
    Returns all dashboard data in one response:
    1. assigned_issues   — current user's issues grouped by status
    2. my_projects       — projects with open/done counts
    3. active_sprints    — active sprint progress per project
    4. issue_type_counts — counts by type for pie chart
    5. recent_activity   — last 20 activity log entries across all user's issues
    6. unread_notifications — unread notification count + latest 10
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from issues.models import Issue, ActivityLog
        from projects.models import Project, Sprint
        from .models import Notification
        from .serializers import NotificationSerializer

        user = request.user

        # ── 1. Assigned issues grouped by status ──
        assigned_issues = Issue.objects.filter(
            assignee=user
        ).select_related("project", "assignee", "reporter").order_by("-updated_at")[:50]

        def issue_brief(i):
            return {
                "id": i.id,
                "title": i.title,
                "project_key": i.project.key,
                "project_name": i.project.name,
                "project_id": i.project.id,
                "priority": i.priority,
                "issue_type": i.issue_type,
                "status": i.status,
                "due_date": str(i.due_date) if i.due_date else None,
                "updated_at": i.updated_at.isoformat(),
            }

        grouped_statuses = {"TODO": [], "IN_PROGRESS": [], "DONE": []}
        for issue in assigned_issues:
            key = issue.status if issue.status in grouped_statuses else "TODO"
            grouped_statuses[key].append(issue_brief(issue))

        # ── 2. My projects with open/done counts ──
        projects = Project.objects.filter(
            memberships__user=user
        ).distinct().prefetch_related("issues")

        my_projects = []
        for p in projects:
            all_issues = p.issues.all()
            my_projects.append({
                "id": p.id,
                "name": p.name,
                "key": p.key,
                "total": all_issues.count(),
                "open": all_issues.filter(status__in=["TODO", "IN_PROGRESS"]).count(),
                "done": all_issues.filter(status="DONE").count(),
                "my_role": p.memberships.filter(user=user).values_list("role", flat=True).first(),
            })

        # ── 3. Active sprint progress ──
        active_sprints = Sprint.objects.filter(
            project__memberships__user=user,
            status="ACTIVE"
        ).distinct().select_related("project")

        sprint_data = []
        for s in active_sprints:
            sprint_issues = s.issues.all()
            total = sprint_issues.count()
            done = sprint_issues.filter(status="DONE").count()
            sprint_data.append({
                "id": s.id,
                "name": s.name,
                "project_name": s.project.name,
                "project_id": s.project.id,
                "goal": s.goal,
                "start_date": str(s.start_date) if s.start_date else None,
                "end_date": str(s.end_date) if s.end_date else None,
                "total": total,
                "done": done,
                "in_progress": sprint_issues.filter(status="IN_PROGRESS").count(),
                "todo": sprint_issues.filter(status="TODO").count(),
                "percent": round((done / total) * 100) if total else 0,
            })

        # ── 4. Issue type counts (for pie chart) ──
        all_user_issues = Issue.objects.filter(
            project__memberships__user=user
        ).distinct()

        type_counts = {}
        for t in ["TASK", "BUG", "STORY", "EPIC"]:
            type_counts[t] = all_user_issues.filter(issue_type=t).count()

        # ── 5. Recent activity log (last 20 entries across user's projects) ──
        activity = ActivityLog.objects.filter(
            issue__project__memberships__user=user
        ).select_related("actor", "issue", "issue__project").order_by("-created_at")[:20]

        activity_data = []
        for a in activity:
            activity_data.append({
                "id": a.id,
                "actor": a.actor.username if a.actor else "System",
                "field_changed": a.field_changed,
                "old_value": a.old_value,
                "new_value": a.new_value,
                "issue_id": a.issue.id,
                "issue_title": a.issue.title,
                "project_key": a.issue.project.key,
                "project_id": a.issue.project.id,
                "created_at": a.created_at.isoformat(),
            })

        # ── 6. Unread notifications ──
        unread_qs = Notification.objects.filter(
            recipient=user, read=False
        ).select_related("actor").order_by("-created_at")

        unread_count = unread_qs.count()
        recent_notifs = []
        for n in unread_qs[:10]:
            recent_notifs.append({
                "id": n.id,
                "actor": n.actor.username if n.actor else "System",
                "action": n.action,
                "target": n.target,
                "created_at": n.created_at.isoformat(),
            })

        return Response({
            "assigned_by_status": grouped_statuses,
            "my_projects": my_projects,
            "active_sprints": sprint_data,
            "issue_type_counts": type_counts,
            "recent_activity": activity_data,
            "unread_notifications": {
                "count": unread_count,
                "items": recent_notifs,
            },
        })
