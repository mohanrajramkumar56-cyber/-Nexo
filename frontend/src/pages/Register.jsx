import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import api from "../api/client";

export default function Register() {
  const [step, setStep] = useState(1); // 1: form, 2: verify OTP code
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [otpCode, setOtpCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const [resendSuccess, setResendSuccess] = useState("");

  const { register, verifyCode } = useAuth();
  const navigate = useNavigate();

  // Handle countdown timer for resend
  useEffect(() => {
    let timer;
    if (resendCooldown > 0) {
      timer = setTimeout(() => setResendCooldown((prev) => prev - 1), 1000);
    }
    return () => clearTimeout(timer);
  }, [resendCooldown]);

  const hasMinLength = password.length >= 8;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>\-_=+[\]\\;/`~]/.test(password);
  const isPasswordValid = hasMinLength && hasUpper && hasLower && hasNumber && hasSpecial;

  // Username validation
  const isUsernameFormatValid = /^[a-zA-Z0-9_]{3,20}$/.test(username);
  const usernameHint = username.length === 0
    ? ""
    : !isUsernameFormatValid
    ? "3–20 chars: letters, numbers, underscores only."
    : "✓ Looks good!";

  // Step 1: Submit Registration
  async function handleRegisterSubmit(e) {
    e.preventDefault();
    if (!email.trim() || !password || !username.trim()) {
      setError("Please fill out all required fields.");
      return;
    }
    if (!isUsernameFormatValid) {
      setError("Username must be 3–20 characters and contain only letters, numbers, or underscores.");
      return;
    }
    if (!isPasswordValid) {
      setError("Password does not meet the security requirements (min 8 chars with uppercase, lowercase, number, and special symbol).");
      return;
    }
    setError("");
    setResendSuccess("");
    setLoading(true);
    try {
      const res = await register(password, email.trim().toLowerCase(), username.trim());
      if (res?.require_verification) {
        setStep(2);
        setResendCooldown(30);
      } else {
        navigate("/projects");
      }
    } catch (err) {
      const getFieldError = (value) => {
        if (Array.isArray(value)) return value[0] || "";
        return typeof value === "string" ? value : "";
      };
      const emailErr = getFieldError(err?.response?.data?.email);
      const usernameErr = getFieldError(err?.response?.data?.username);
      const pwdErr = getFieldError(err?.response?.data?.password);
      const detailErr = err?.response?.data?.detail;
      const statusErr = err?.response?.status
        ? `Server error ${err.response.status}. Please try again after the latest deployment finishes.`
        : "";

      const msg =
        usernameErr ||
        pwdErr ||
        emailErr ||
        detailErr ||
        statusErr ||
        "Could not create account. Please check the entered information.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  // Step 2: Verify 6-digit OTP Code
  async function handleVerifyOtpSubmit(e) {
    e.preventDefault();
    const cleanCode = otpCode.trim();
    if (cleanCode.length !== 6) {
      setError("Please enter the complete 6-digit verification code.");
      return;
    }
    setError("");
    setResendSuccess("");
    setLoading(true);
    try {
      await verifyCode(email.trim().toLowerCase(), cleanCode, "REGISTRATION");
      navigate("/projects");
    } catch (err) {
      const msg = err?.response?.data?.detail || "Invalid or expired verification code. Please try again.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  // Resend fresh OTP code
  async function handleResendCode() {
    if (resendCooldown > 0) return;
    setError("");
    setResendSuccess("");
    setLoading(true);
    try {
      const res = await api.post("/auth/resend-code/", {
        email: email.trim().toLowerCase(),
        purpose: "REGISTRATION",
      });
      setResendSuccess(res.data?.detail || "A fresh verification code has been sent!");
      setResendCooldown(30);
    } catch (err) {
      const msg = err?.response?.data?.detail || "Could not resend code. Please try again.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="jira-auth-page">
      {/* Dynamic Background Elements */}
      <div className="jira-auth-bg-blob jira-auth-bg-blob-1"></div>
      <div className="jira-auth-bg-blob jira-auth-bg-blob-2"></div>
      <div className="jira-auth-bg-pattern"></div>

      <div className="jira-auth-container jira-auth-single-card">
        {/* Auth Form Card */}
        <div className="jira-auth-card">
          <div className="jira-auth-card-inner">
            {/* Top Brand Logo */}
            <div className="jira-auth-header-brand" style={{ flexDirection: "column", alignItems: "center", gap: 8, paddingBottom: 8 }}>
              <img src="/dp-logo.png" alt="DataPattern Logo" style={{ height: 40, width: "auto", objectFit: "contain" }} />
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
                <span className="jira-auth-brand-name" style={{ fontSize: 22, fontWeight: 800, letterSpacing: 2, color: "#172B4D" }}>NEXO</span>
                <span style={{ fontSize: 11, color: "#6B778C", letterSpacing: 0.5 }}>Powered by DataPattern</span>
              </div>
            </div>

            {/* Header / Nav switcher */}
            <div className="jira-auth-tabs">
              <Link to="/login" className="jira-auth-tab">
                Log In
              </Link>
              <button
                type="button"
                className="jira-auth-tab active"
                disabled
              >
                Sign Up
              </button>
            </div>

            <div className="jira-auth-title-area">
              <h2 className="jira-auth-main-title">
                {step === 1 ? "Create your account" : "Verify your email"}
              </h2>
              <p className="jira-auth-main-subtitle">
                {step === 1
                  ? "Sign up to start planning sprints and organizing your team issues."
                  : `Enter the 6-digit verification code sent to ${email}`}
              </p>
            </div>

            {error && (
              <div className="jira-auth-alert-error">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="12" y1="8" x2="12" y2="12"></line>
                  <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <div className="jira-auth-alert-msg">{error}</div>
              </div>
            )}

            {resendSuccess && (
              <div className="jira-auth-verified-badge" style={{ marginBottom: 16 }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#006644" strokeWidth="2.5">
                  <polyline points="20 6 9 17 4 12"></polyline>
                </svg>
                <span>{resendSuccess}</span>
              </div>
            )}

            {/* STEP 1: Registration Form */}
            {step === 1 && (
              <form onSubmit={handleRegisterSubmit} className="jira-auth-form">
                {/* Username Field */}
                <div className="jira-form-group">
                  <label className="jira-form-label" htmlFor="register-username">
                    Username <span style={{ color: "#DE350B" }}>*</span>
                  </label>
                  <div className="jira-input-wrapper">
                    <span className="jira-input-icon">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                        <circle cx="12" cy="7" r="4"/>
                      </svg>
                    </span>
                    <input
                      id="register-username"
                      type="text"
                      className="jira-form-input"
                      placeholder="e.g. john_doe (shown to teammates)"
                      value={username}
                      onChange={(e) => setUsername(e.target.value.replace(/\s/g, ""))}
                      autoComplete="username"
                      maxLength={20}
                      required
                    />
                    <span style={{
                      position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)",
                      fontSize: 11, color: "#6B778C", pointerEvents: "none"
                    }}>{username.length}/20</span>
                  </div>
                  {usernameHint && (
                    <span style={{
                      fontSize: 11.5,
                      marginTop: 3,
                      color: isUsernameFormatValid ? "#006644" : "#DE350B",
                    }}>
                      {usernameHint}
                    </span>
                  )}
                </div>

                {/* Email Field */}
                <div className="jira-form-group">
                  <label className="jira-form-label" htmlFor="register-email">
                    Email Address <span style={{ color: "#DE350B" }}>*</span>
                  </label>
                  <div className="jira-input-wrapper">
                    <span className="jira-input-icon">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                        <polyline points="22,6 12,13 2,6"></polyline>
                      </svg>
                    </span>
                    <input
                      id="register-email"
                      type="email"
                      className="jira-form-input"
                      placeholder="alex@company.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      autoComplete="email"
                      required
                    />
                  </div>
                  <span style={{ fontSize: 11.5, color: "#6B778C", marginTop: 2 }}>
                    Must be a permanent, reachable email address (no disposable domains).
                  </span>
                </div>

                <div className="jira-form-group">
                  <div className="jira-form-label-row">
                    <label className="jira-form-label" htmlFor="register-password">
                      Password <span style={{ color: "#DE350B" }}>*</span>
                    </label>
                  </div>
                  <div className="jira-input-wrapper">
                    <span className="jira-input-icon">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                      </svg>
                    </span>
                    <input
                      id="register-password"
                      type={showPassword ? "text" : "password"}
                      className="jira-form-input"
                      placeholder="Create strong password (min. 8 chars)"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="new-password"
                      required
                    />
                    <button
                      type="button"
                      className="jira-input-action-btn"
                      onClick={() => setShowPassword(!showPassword)}
                      title={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                          <line x1="1" y1="1" x2="23" y2="23"></line>
                        </svg>
                      ) : (
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8z"></path>
                          <circle cx="12" cy="12" r="3"></circle>
                        </svg>
                      )}
                    </button>
                  </div>

                  {/* Real-time Password Requirements Checklist */}
                  <div className="jira-pwd-requirements-card">
                    <div className="jira-pwd-req-title">Password must contain:</div>
                    <div className="jira-pwd-req-grid">
                      <div className={`jira-pwd-req-item ${hasMinLength ? "satisfied" : ""}`}>
                        <span className="jira-pwd-req-icon">{hasMinLength ? "✓" : "○"}</span>
                        <span>8+ characters</span>
                      </div>
                      <div className={`jira-pwd-req-item ${hasUpper ? "satisfied" : ""}`}>
                        <span className="jira-pwd-req-icon">{hasUpper ? "✓" : "○"}</span>
                        <span>Uppercase (A-Z)</span>
                      </div>
                      <div className={`jira-pwd-req-item ${hasLower ? "satisfied" : ""}`}>
                        <span className="jira-pwd-req-icon">{hasLower ? "✓" : "○"}</span>
                        <span>Lowercase (a-z)</span>
                      </div>
                      <div className={`jira-pwd-req-item ${hasNumber ? "satisfied" : ""}`}>
                        <span className="jira-pwd-req-icon">{hasNumber ? "✓" : "○"}</span>
                        <span>Number (0-9)</span>
                      </div>
                      <div className={`jira-pwd-req-item ${hasSpecial ? "satisfied" : ""}`}>
                        <span className="jira-pwd-req-icon">{hasSpecial ? "✓" : "○"}</span>
                        <span>Special symbol (@$!%*)</span>
                      </div>
                    </div>
                  </div>
                </div>

                <button
                  type="submit"
                  className="jira-auth-submit-btn"
                  disabled={loading}
                >
                  {loading ? (
                    <span className="jira-btn-spinner-wrap">
                      <span className="jira-btn-spinner"></span>
                      Sending Verification Code...
                    </span>
                  ) : (
                    <span>Continue &rarr;</span>
                  )}
                </button>
              </form>
            )}

            {/* STEP 2: Enter 6-digit Verification Code */}
            {step === 2 && (
              <form onSubmit={handleVerifyOtpSubmit} className="jira-auth-form">
                <div className="jira-auth-otp-hero">
                  <div className="jira-auth-otp-badge">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#0052CC" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                      <polyline points="22,6 12,13 2,6"></polyline>
                    </svg>
                  </div>
                  <span className="jira-auth-otp-email-label">{email}</span>
                </div>

                <div className="jira-form-group">
                  <label className="jira-form-label" htmlFor="otp-input" style={{ textAlign: "center", display: "block" }}>
                    Enter 6-Digit Code
                  </label>
                  <input
                    id="otp-input"
                    type="text"
                    className="jira-form-input jira-otp-input-field"
                    placeholder="• • • • • •"
                    maxLength={6}
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value.replace(/[^0-9]/g, ""))}
                    autoFocus
                    required
                  />
                  <span style={{ fontSize: 12, color: "#6B778C", textAlign: "center", display: "block", marginTop: 4 }}>
                    Code expires in 15 minutes.
                  </span>
                </div>

                <button
                  type="submit"
                  className="jira-auth-submit-btn"
                  disabled={loading || otpCode.length !== 6}
                >
                  {loading ? (
                    <span className="jira-btn-spinner-wrap">
                      <span className="jira-btn-spinner"></span>
                      Verifying Code...
                    </span>
                  ) : (
                    <span>Verify & Access Workspace &rarr;</span>
                  )}
                </button>

                <div className="jira-auth-resend-row">
                  <button
                    type="button"
                    className="jira-btn-resend"
                    onClick={handleResendCode}
                    disabled={resendCooldown > 0 || loading}
                  >
                    {resendCooldown > 0 ? `Resend code in ${resendCooldown}s` : "Resend Code"}
                  </button>
                  <button
                    type="button"
                    className="jira-btn-change-email"
                    onClick={() => {
                      setStep(1);
                      setError("");
                    }}
                  >
                    Change Email
                  </button>
                </div>
              </form>
            )}

            <div className="jira-auth-divider">
              <span>Already registered?</span>
            </div>

            <div className="jira-auth-switch-prompt">
              Already have an account?{" "}
              <Link to="/login" className="jira-auth-link">
                Log in here
              </Link>
            </div>

            <div className="jira-auth-legal">
              By creating an account, you agree to the NEXO Terms of Service and Privacy Policy.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

