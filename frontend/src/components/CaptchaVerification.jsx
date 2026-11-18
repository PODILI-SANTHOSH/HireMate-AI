import { useCallback, useEffect, useRef, useState } from "react";

export default function CaptchaVerification({
  apiBaseUrl,
  purpose,
  onChange = () => {},
  onLoadingChange = () => {},
  refreshKey,
  error,
  label = "Security check",
}) {
  const [challenge, setChallenge] = useState(null);
  const [answer, setAnswer] = useState("");
  const [loading, setLoading] = useState(false);
  const [imageLoading, setImageLoading] = useState(false);
  const [imageError, setImageError] = useState(false);
  const [loadError, setLoadError] = useState("");
  const challengeIdRef = useRef("");

  useEffect(() => {
    if (typeof onLoadingChange === "function") {
      onLoadingChange(loading || imageLoading);
    }
  }, [imageLoading, loading, onLoadingChange]);

  const refreshCaptcha = useCallback(async () => {
    const previousChallengeId = challengeIdRef.current;
    challengeIdRef.current = "";
    setLoading(true);
    setImageLoading(false);
    setImageError(false);
    setLoadError("");
    setAnswer("");
    setChallenge(null);
    onChange({ challengeId: "", answer: "" });

    try {
      const query = new URLSearchParams({ purpose });
      if (previousChallengeId) {
        query.set("previous_challenge_id", previousChallengeId);
      }
      const response = await fetch(
        `${apiBaseUrl}/auth/captcha?${query.toString()}`,
        {
          cache: "no-store",
        }
      );
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Could not load a CAPTCHA challenge.");
      }

      const encodedImage = data.image?.split(",")[1];
      if (
        typeof data.challenge_id !== "string" ||
        !data.image?.startsWith("data:image/png;base64,") ||
        !encodedImage ||
        !/^[A-Za-z0-9+/]+={0,2}$/.test(encodedImage)
      ) {
        throw new Error("The server returned invalid CAPTCHA image data.");
      }

      challengeIdRef.current = data.challenge_id;
      setChallenge(data);
      setImageLoading(true);
      onChange({ challengeId: data.challenge_id, answer: "" });
    } catch (requestError) {
      setLoadError(
        requestError instanceof TypeError
          ? `Cannot connect to the authentication API at ${apiBaseUrl}. Confirm the backend is running and check its CORS configuration.`
          : requestError.message || "Could not load a CAPTCHA challenge."
      );
    } finally {
      setLoading(false);
    }
  }, [apiBaseUrl, onChange, purpose]);

  useEffect(() => {
    const timer = window.setTimeout(refreshCaptcha, 0);
    return () => window.clearTimeout(timer);
  }, [refreshCaptcha, refreshKey]);

  const handleAnswerChange = (event) => {
    const nextAnswer = event.target.value
      .toUpperCase()
      .replace(/[^ABCDEFGHJKLMNPQRSTUVWXYZ23456789]/g, "")
      .slice(0, 6);
    setAnswer(nextAnswer);
    onChange({
      challengeId: challenge?.challenge_id || "",
      answer: nextAnswer,
    });
  };

  const handleImageLoad = (event) => {
    const { naturalWidth, naturalHeight } = event.currentTarget;
    if (naturalWidth < 200 || naturalHeight < 50) {
      setImageError(true);
      setLoadError("The CAPTCHA image is blank or incomplete. Refresh to try again.");
      setAnswer("");
      onChange({ challengeId: "", answer: "" });
      setImageLoading(false);
      return;
    }

    setLoadError("");
    setImageLoading(false);
  };

  const handleImageError = () => {
    setImageError(true);
    setLoadError("The CAPTCHA image could not be displayed. Refresh to try again.");
    setAnswer("");
    onChange({ challengeId: "", answer: "" });
    setImageLoading(false);
  };

  return (
    <div className="captcha-field">
      <label htmlFor="auth-captcha-answer">{label}</label>
      <div className="captcha-challenge">
        {challenge && !imageError ? (
          <img
            className="captcha-image"
            src={challenge.image}
            alt="CAPTCHA challenge"
            width="280"
            height="82"
            onLoad={handleImageLoad}
            onError={handleImageError}
          />
        ) : (
          <div className="captcha-placeholder" aria-live="polite">
            {loading
              ? "Loading CAPTCHA…"
              : imageError
                ? "CAPTCHA image could not be displayed."
                : "CAPTCHA unavailable. Refresh to try again."}
          </div>
        )}
        <button
          className="captcha-refresh"
          type="button"
          onClick={refreshCaptcha}
          disabled={loading}
          aria-label="Refresh CAPTCHA"
          title="Refresh CAPTCHA"
        >
          <svg
            aria-hidden="true"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M20 7v5h-5" />
            <path d="M4.6 9a7.5 7.5 0 0 1 12.7-2L20 12M4 17v-5h5" />
            <path d="M19.4 15a7.5 7.5 0 0 1-12.7 2L4 12" />
          </svg>
        </button>
      </div>
      <input
        id="auth-captcha-answer"
        type="text"
        value={answer}
        onChange={handleAnswerChange}
        placeholder="Enter the characters shown"
        autoComplete="off"
        autoCapitalize="characters"
        spellCheck="false"
        maxLength={6}
        aria-describedby="auth-captcha-help auth-captcha-error"
        disabled={loading || imageLoading || imageError || !challenge}
      />
      <p className="captcha-help" id="auth-captcha-help">
        Enter the 6 uppercase letters and numbers.
      </p>
      {(error || loadError) && (
        <p
          className="captcha-error"
          id="auth-captcha-error"
          role="alert"
        >
          {error || loadError}
        </p>
      )}
      {(loading || imageLoading) && (
        <span className="captcha-loading" role="status">
          Loading CAPTCHA…
        </span>
      )}
    </div>
  );
}
