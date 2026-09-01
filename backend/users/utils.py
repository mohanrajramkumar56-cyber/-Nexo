import random
import re
import socket
import logging
import smtplib
from dataclasses import dataclass
from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmailDeliveryResult:
    """Safe mail-delivery outcome for API responses and logs."""

    sent: bool
    reason: str = ""

    def __bool__(self):
        return self.sent

# Blocklist of popular disposable / temporary email domains
DISPOSABLE_DOMAINS = {
    "tempmail.com", "temp-mail.org", "temp-mail.io", "tempmailo.com",
    "mailinator.com", "mailinator.net", "mailinator2.com",
    "10minutemail.com", "10minutemail.net", "10minmail.com",
    "guerrillamail.com", "guerrillamail.net", "guerrillamail.biz", "guerrillamail.org",
    "sharklasers.com", "grr.la", "guerrillamailblock.com",
    "trashmail.com", "trashmail.net", "trashmail.org",
    "yopmail.com", "yopmail.fr", "yopmail.net",
    "dispostable.com", "getairmail.com", "fakeinbox.com",
    "throwawaymail.com", "mytemp.email", "mohmal.com",
    "crazymailing.com", "generator.email", "armyspy.com",
    "cuvox.de", "dayrep.com", "einrot.com", "fleckens.hu",
    "gustr.com", "jourrapide.com", "rhyta.com", "superrito.com",
    "teleworm.us", "inboxkitten.com", "burnermail.io",
}


def is_disposable_domain(email: str) -> bool:
    """Checks if the email domain is in the known disposable/throwaway blocklist."""
    if not email or "@" not in email:
        return False
    domain = email.strip().split("@")[-1].lower()
    return domain in DISPOSABLE_DOMAINS


def validate_email_deliverability(email: str) -> tuple[bool, str]:
    """
    Validates format, checks disposable blocklist, and optionally verifies domain DNS.
    Returns (is_valid, error_message).
    """
    email = email.strip().lower()
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, email):
        return False, "Invalid email address format."

    domain = email.split("@")[-1]

    # Check throwaway / disposable domains
    if is_disposable_domain(email):
        return False, f"Disposable email domain '@{domain}' is not allowed. Please use a permanent email address."

    # Verify domain has valid DNS structure
    try:
        # Check if domain resolves
        socket.gethostbyname(domain)
    except (socket.gaierror, socket.herror, Exception):
        return False, f"The email domain '@{domain}' does not exist or cannot receive mail."

    return True, ""


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validates password strength:
    - Minimum 8 characters (8+ characters)
    - At least one uppercase letter [A-Z]
    - At least one lowercase letter [a-z]
    - At least one numeric digit [0-9]
    - At least one special symbol (e.g. @, #, $, %, !, *)
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number (0-9)."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;/`~]', password):
        return False, "Password must contain at least one special symbol (e.g. @, #, $, %, !, *)."
    return True, ""


def generate_otp_code(length: int = 6) -> str:
    """Generates a secure numeric verification code (e.g. 849201)."""
    return "".join([str(random.randint(0, 9)) for _ in range(length)])


def send_verification_email(email: str, code: str, purpose: str = "REGISTRATION", username: str = "") -> EmailDeliveryResult:
    """
    Dispatches a formatted verification email with the 6-digit OTP code.
    Uses Django's send_mail (console backend in dev, SMTP in prod).
    """
    subject = "NEXO - Your Verification Code"
    if purpose == "PASSWORD_RESET":
        subject = "NEXO - Password Reset Code"

    purpose_text = "verify your email address and activate your account" if purpose == "REGISTRATION" else "reset your account password"

    message = f"""Hello {username or 'there'},

Your NEXO verification code is:

    ======================
           {code}
    ======================

Use this 6-digit code to {purpose_text}.
This code is valid for 15 minutes.

If you did not request this code, please ignore this email.

Best regards,
The NEXO Team
"""

    html_message = f"""
    <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; border: 1px solid #DFE1E6; border-radius: 8px; background: #FFFFFF;">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 20px;">
            <h2 style="color: #0052CC; margin: 0;">NEXO</h2>
        </div>
        <h3 style="color: #172B4D; margin-top: 0;">{ 'Activate Your Account' if purpose == 'REGISTRATION' else 'Reset Your Password' }</h3>
        <p style="color: #42526E; font-size: 14px; line-height: 1.5;">
            Use the 6-digit verification code below to {purpose_text}:
        </p>
        <div style="background: #F4F5F7; border: 2px dashed #0052CC; border-radius: 8px; padding: 18px; text-align: center; margin: 24px 0;">
            <span style="font-family: monospace; font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #0052CC;">{code}</span>
        </div>
        <p style="color: #6B778C; font-size: 13px;">
            ⏰ This code will expire in <strong>15 minutes</strong>.
        </p>
        <hr style="border: none; border-top: 1px solid #EBECF0; margin: 24px 0;" />
        <p style="color: #8993A4; font-size: 12px; margin: 0;">
            If you did not request this email, you can safely ignore it.
        </p>
    </div>
    """

    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@jira-software.local")

    try:
        import ssl
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        # Build the email message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = email
        msg.attach(MIMEText(message, "plain"))
        msg.attach(MIMEText(html_message, "html"))

        # Use verified TLS for SMTP in production.
        context = ssl.create_default_context()

        host = getattr(settings, "EMAIL_HOST", "smtp.gmail.com")
        port = getattr(settings, "EMAIL_PORT", 587)
        user = getattr(settings, "EMAIL_HOST_USER", "")
        password = getattr(settings, "EMAIL_HOST_PASSWORD", "")

        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(user, password)
            server.sendmail(from_email, [email], msg.as_string())

        return EmailDeliveryResult(sent=True)
    except smtplib.SMTPAuthenticationError:
        logger.exception("[Email Dispatch Error] Gmail rejected SMTP authentication")
        return EmailDeliveryResult(
            sent=False,
            reason="The email sender could not sign in to Gmail. The app owner must set EMAIL_HOST_PASSWORD to a current 16-character Google App Password.",
        )
    except (smtplib.SMTPConnectError, TimeoutError, OSError):
        logger.exception("[Email Dispatch Error] SMTP connection failed")
        return EmailDeliveryResult(
            sent=False,
            reason="The email service could not connect to Gmail. Please try again later.",
        )
    except smtplib.SMTPRecipientsRefused:
        logger.exception("[Email Dispatch Error] Recipient address was rejected")
        return EmailDeliveryResult(
            sent=False,
            reason="Gmail rejected this recipient address. Please check the email address and try again.",
        )
    except Exception:
        # Vercel Runtime Logs capture this traceback, while the API returns a
        # safe generic message to users without exposing SMTP credentials.
        logger.exception("[Email Dispatch Error] Verification email delivery failed")
        return EmailDeliveryResult(
            sent=False,
            reason="The email service could not send the verification message. Please try again later.",
        )


def send_assignment_email(assignee_email: str, assignee_username: str, issue_title: str,
                          issue_key: str, project_name: str, assigned_by: str,
                          project_id: int = None, issue_id: int = None) -> bool:
    """Kept for backward compatibility — delegates to send_notification_email."""
    return send_notification_email(
        recipient_email=assignee_email,
        recipient_username=assignee_username,
        actor=assigned_by,
        action="assigned you to",
        issue_key=issue_key,
        issue_title=issue_title,
        project_name=project_name,
        project_id=project_id,
        issue_id=issue_id,
        why_reason="assignee",
    )


def send_mention_email(mentioned_email: str, mentioned_username: str, mentioned_by: str,
                       issue_title: str, issue_key: str, project_name: str,
                       comment_body: str) -> bool:
    """Kept for backward compatibility — delegates to send_notification_email."""
    return send_notification_email(
        recipient_email=mentioned_email,
        recipient_username=mentioned_username,
        actor=mentioned_by,
        action="mentioned you in a comment on",
        issue_key=issue_key,
        issue_title=issue_title,
        project_name=project_name,
        why_reason="mention",
        comment_body=comment_body,
    )


def send_comment_email(recipient_email: str, recipient_username: str, commenter: str,
                       issue_title: str, issue_key: str, project_name: str,
                       comment_body: str, is_mention: bool = False,
                       project_id: int = None, issue_id: int = None) -> bool:
    """Kept for backward compatibility — delegates to send_notification_email."""
    return send_notification_email(
        recipient_email=recipient_email,
        recipient_username=recipient_username,
        actor=commenter,
        action="mentioned you in a comment on" if is_mention else "commented on",
        issue_key=issue_key,
        issue_title=issue_title,
        project_name=project_name,
        project_id=project_id,
        issue_id=issue_id,
        why_reason="mention" if is_mention else "assignee",
        comment_body=comment_body,
    )


# ─────────────────────────────────────────────────────────────────────────────
# SHARED NOTIFICATION EMAIL — single source of truth for all notification emails
# ─────────────────────────────────────────────────────────────────────────────
def send_notification_email(
    recipient_email: str,
    recipient_username: str,
    actor: str,
    action: str,
    issue_key: str,
    issue_title: str,
    project_name: str,
    project_id: int = None,
    issue_id: int = None,
    why_reason: str = "assignee",
    comment_body: str = None,
    issue_type: str = None,
    issue_priority: str = None,
    issue_status: str = None,
    issue_reporter: str = None,
    issue_assignee: str = None,
) -> bool:
    """
    Unified NEXO notification email matching real Jira's structure:

    Header  : NEXO logo + app name
    Action  : "[Actor] [action] on [Issue Key]"
    Issue   : Key, Title, Type, Priority, Status, Reporter, Assignee
    Comment : (only for comment/mention) — commenter name + full comment text
    Button  : View Issue →
    Footer  : Why you're receiving this
    """
    frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:5173")
    issue_url = (
        f"{frontend_url}/projects/{project_id}/board?issue={issue_id}"
        if project_id and issue_id
        else f"{frontend_url}/projects"
    )

    # Subject line
    subject_map = {
        "assignee": f"[NEXO] {actor} assigned you to {issue_key}",
        "reporter": f"[NEXO] New activity on your issue {issue_key}",
        "mention":  f"[NEXO] {actor} mentioned you in {issue_key}",
    }
    subject = subject_map.get(why_reason, f"[NEXO] Update on {issue_key}")

    # Footer reason
    footer_map = {
        "assignee": f"You're receiving this email because you are the <strong>assignee</strong> on this issue.",
        "reporter": f"You're receiving this email because you are the <strong>reporter</strong> on this issue.",
        "mention":  f"You're receiving this email because you were <strong>mentioned</strong> in this issue.",
    }
    footer_reason = footer_map.get(why_reason, "You're receiving this email because you are a member of this project.")

    # Issue card rows
    issue_rows = ""
    if issue_type:
        issue_rows += f"<tr><td style='color:#6B778C;padding:3px 0;font-size:13px;width:110px'>Type</td><td style='font-size:13px;color:#172B4D'>{issue_type}</td></tr>"
    if issue_priority:
        issue_rows += f"<tr><td style='color:#6B778C;padding:3px 0;font-size:13px'>Priority</td><td style='font-size:13px;color:#172B4D'>{issue_priority}</td></tr>"
    if issue_status:
        issue_rows += f"<tr><td style='color:#6B778C;padding:3px 0;font-size:13px'>Status</td><td style='font-size:13px;color:#172B4D'>{issue_status}</td></tr>"
    if issue_reporter:
        issue_rows += f"<tr><td style='color:#6B778C;padding:3px 0;font-size:13px'>Reporter</td><td style='font-size:13px;color:#172B4D'>{issue_reporter}</td></tr>"
    if issue_assignee:
        issue_rows += f"<tr><td style='color:#6B778C;padding:3px 0;font-size:13px'>Assignee</td><td style='font-size:13px;color:#172B4D'>{issue_assignee}</td></tr>"

    # Comment block (only for comment/mention emails)
    comment_block = ""
    if comment_body:
        preview = comment_body[:400] + ("..." if len(comment_body) > 400 else "")
        comment_block = f"""
        <div style="margin: 20px 0;">
            <p style="font-size: 12px; font-weight: 700; color: #6B778C; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;">
                Comment by {actor}
            </p>
            <div style="background: #F8F9FF; border-left: 4px solid #6554C0; border-radius: 0 6px 6px 0;
                        padding: 14px 16px; font-size: 14px; color: #172B4D; line-height: 1.6;">
                {preview}
            </div>
        </div>
        """

    html_message = f"""
    <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto;
                border: 1px solid #DFE1E6; border-radius: 10px; overflow: hidden; background: #FFFFFF;">

        <!-- HEADER -->
        <div style="background: linear-gradient(135deg, #0052CC, #6554C0); padding: 18px 24px; display: flex; align-items: center; gap: 10px;">
            <span style="color: #FFFFFF; font-size: 20px; font-weight: 800; letter-spacing: 1px;">NEXO</span>
            <span style="color: rgba(255,255,255,0.6); font-size: 12px;">Powered by DataPattern</span>
        </div>

        <!-- BODY -->
        <div style="padding: 24px;">

            <!-- ACTION LINE -->
            <p style="font-size: 15px; color: #172B4D; margin: 0 0 20px 0; line-height: 1.5;">
                <strong>{actor}</strong> {action}
                <strong>{issue_key}</strong> in <strong>{project_name}</strong>.
            </p>

            <!-- ISSUE CARD -->
            <div style="background: #F4F5F7; border-radius: 8px; padding: 16px 18px; margin-bottom: 20px;">
                <div style="font-size: 11px; color: #6B778C; font-weight: 700; text-transform: uppercase;
                            letter-spacing: 0.6px; margin-bottom: 6px;">{project_name} &nbsp;·&nbsp; {issue_key}</div>
                <div style="font-size: 17px; font-weight: 700; color: #172B4D; margin-bottom: 12px;">{issue_title}</div>
                {f'<table style="border-collapse:collapse">{issue_rows}</table>' if issue_rows else ""}
            </div>

            <!-- COMMENT BLOCK (only for comment/mention emails) -->
            {comment_block}

            <!-- VIEW ISSUE BUTTON -->
            <a href="{issue_url}"
               style="display: inline-block; padding: 11px 24px;
                      background: linear-gradient(135deg, #0065FF, #0052CC);
                      color: #FFFFFF; font-weight: 700; font-size: 14px;
                      border-radius: 8px; text-decoration: none;
                      box-shadow: 0 2px 8px rgba(0,82,204,0.35); margin-bottom: 24px;">
                View Issue →
            </a>

        </div>

        <!-- FOOTER -->
        <div style="background: #F4F5F7; border-top: 1px solid #EBECF0; padding: 14px 24px;">
            <p style="color: #6B778C; font-size: 12px; margin: 0; line-height: 1.6;">
                {footer_reason}
            </p>
        </div>
    </div>
    """

    plain_message = (
        f"Hello {recipient_username},\n\n"
        f"{actor} {action} {issue_key} — {issue_title} in {project_name}.\n\n"
        f"{('Comment: ' + comment_body[:300]) if comment_body else ''}\n\n"
        f"View issue: {issue_url}\n\n"
        f"The NEXO Team\n"
    )

    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@NEXO.local")

    try:
        import ssl, smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = recipient_email
        msg.attach(MIMEText(plain_message, "plain"))
        msg.attach(MIMEText(html_message, "html"))

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        host = getattr(settings, "EMAIL_HOST", "smtp.gmail.com")
        port = getattr(settings, "EMAIL_PORT", 587)
        user = getattr(settings, "EMAIL_HOST_USER", "")
        password = getattr(settings, "EMAIL_HOST_PASSWORD", "")

        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(user, password)
            server.sendmail(from_email, [recipient_email], msg.as_string())

        return True
    except Exception as e:
        print(f"[NEXO Email Error]: {e}")
        return False
    """
    Sends an email to the user who has been assigned to an issue.
    """
    subject = f"[NEXO] You've been assigned to {issue_key}"

    # Build deep link if project_id and issue_id are available
    frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:5173")
    if project_id and issue_id:
        issue_url = f"{frontend_url}/projects/{project_id}/board?issue={issue_id}"
    else:
        issue_url = f"{frontend_url}/projects"

    message = f"""Hello {assignee_username},

{assigned_by} has assigned you to the following issue:

    Issue  : {issue_key} — {issue_title}
    Project: {project_name}

Open the issue directly: {issue_url}

Best regards,
The NEXO Team
"""

    html_message = f"""
    <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px;
                border: 1px solid #DFE1E6; border-radius: 8px; background: #FFFFFF;">
        <h2 style="color: #0052CC; margin: 0 0 16px 0;">NEXO</h2>
        <h3 style="color: #172B4D; margin-top: 0;">You've been assigned to an issue</h3>
        <p style="color: #42526E; font-size: 14px; line-height: 1.6;">
            <strong>{assigned_by}</strong> assigned you to:
        </p>
        <div style="background: #F4F5F7; border-left: 4px solid #0052CC; border-radius: 4px;
                    padding: 14px 18px; margin: 16px 0;">
            <div style="font-size: 13px; color: #6B778C; margin-bottom: 4px;">{project_name}</div>
            <div style="font-size: 16px; font-weight: 700; color: #172B4D;">
                {issue_key} — {issue_title}
            </div>
        </div>
        <a href="{issue_url}"
           style="display: inline-block; margin: 8px 0 16px; padding: 10px 22px;
                  background: linear-gradient(135deg, #0065FF, #0052CC);
                  color: #FFFFFF; font-weight: 700; font-size: 14px;
                  border-radius: 7px; text-decoration: none;
                  box-shadow: 0 2px 8px rgba(0,82,204,0.35);">
            Open Issue →
        </a>
        <hr style="border: none; border-top: 1px solid #EBECF0; margin: 20px 0;" />
        <p style="color: #8993A4; font-size: 12px; margin: 0;">
            You received this email because you are a member of <strong>{project_name}</strong>.
        </p>
    </div>
    """

    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@jira-software.local")

    try:
        import ssl
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = assignee_email
        msg.attach(MIMEText(message, "plain"))
        msg.attach(MIMEText(html_message, "html"))

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        host = getattr(settings, "EMAIL_HOST", "smtp.gmail.com")
        port = getattr(settings, "EMAIL_PORT", 587)
        user = getattr(settings, "EMAIL_HOST_USER", "")
        password = getattr(settings, "EMAIL_HOST_PASSWORD", "")

        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(user, password)
            server.sendmail(from_email, [assignee_email], msg.as_string())

        return True
    except Exception as e:
        print(f"[Assignment Email Error]: {e}")
        return False

