
let firebaseKeysCache = null;
let firebaseKeysExpiry = 0;

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function decodeJwtPart(value) {
  return JSON.parse(
    new TextDecoder().decode(decodeBase64Url(value))
  );
}

async function getFirebaseKeys() {
  const now = Date.now();

  if (firebaseKeysCache && now < firebaseKeysExpiry) {
    return firebaseKeysCache;
  }

  const response = await fetch(
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
  );

  if (!response.ok) {
    throw new Error("Unable to retrieve Firebase signing keys");
  }

  const data = await response.json();
  firebaseKeysCache = data.keys || [];
  firebaseKeysExpiry = now + 60 * 60 * 1000;

  return firebaseKeysCache;
}

async function verifyFirebaseToken(request) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) throw new Error("Authentication required");

  const parts = match[1].split(".");
  if (parts.length !== 3) throw new Error("Invalid token");

  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);

  if (header.alg !== "RS256" || !header.kid) {
    throw new Error("Invalid token algorithm");
  }

  const keys = await getFirebaseKeys();
  const jwk = keys.find(key => key.kid === header.kid);

  if (!jwk) throw new Error("Unknown signing key");

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const validSignature = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    decodeBase64Url(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  );

  if (!validSignature) throw new Error("Invalid token signature");

  const now = Math.floor(Date.now() / 1000);

  if (
    payload.aud !== "viraldil" ||
    payload.iss !== "https://securetoken.google.com/viraldil" ||
    !payload.sub ||
    payload.sub.length > 128 ||
    !payload.exp ||
    payload.exp <= now ||
    !payload.iat ||
    payload.iat > now + 60 ||
    !payload.auth_time ||
    payload.auth_time > now + 60 ||
    !payload.email ||
    typeof payload.email !== "string"
  ) {
    throw new Error("Invalid or expired Firebase token");
  }

  return {
    uid: payload.sub,
    email: payload.email.trim().toLowerCase(),
    admin: payload.admin === true
  };
}

async function requireAdmin(request) {
  const user = await verifyFirebaseToken(request);

  if (user.admin !== true) {
    throw new Error("Administrator access required");
  }

  return user;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/api/health" && request.method === "GET") {
      return json({
        success: true,
        app: env.APP_NAME || "ViralDil",
        database: Boolean(env.DB),
        message: "ViralDil Worker is running"
      });
    }

    // ADMIN: List partner applications
    if (
      path === "/api/admin/partners" &&
      request.method === "GET"
    ) {
      if (!env.DB) {
        return json({ success: false, error: "Database is not configured" }, 500);
      }

      try {
        const admin = await requireAdmin(request);

        const result = await env.DB.prepare(
          `SELECT id, full_name, email, country, social_profile,
                  content_category, rights_confirmed, status,
                  created_at, updated_at, reviewed_at, reviewed_by
           FROM partner_applications
           ORDER BY created_at DESC`
        ).all();

        return json({
          success: true,
          partners: result.results || [],
          total: (result.results || []).length
        });
      } catch (error) {
        return json({
          success: false,
          error: error.message === "Administrator access required"
            ? "Admin access denied"
            : "Authentication required"
        }, error.message === "Administrator access required" ? 403 : 401);
      }
    }

    // ADMIN: Update partner application status
    if (
      path.startsWith("/api/admin/partners/") &&
      path.endsWith("/status") &&
      request.method === "POST"
    ) {
      if (!env.DB) {
        return json({ success: false, error: "Database is not configured" }, 500);
      }

      try {
        const admin = await requireAdmin(request);

        const id = decodeURIComponent(
          path.slice("/api/admin/partners/".length, -"/status".length)
        );

        if (!id || id.length > 128 || id.includes("/")) {
          return json({ success: false, error: "Invalid partner ID" }, 400);
        }

        const contentType = request.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
          return json({ success: false, error: "Content-Type must be application/json" }, 415);
        }

        const data = await request.json();
        const status = String(data.status || "").trim();

        if (!["Approved", "Rejected", "Suspended"].includes(status)) {
          return json({
            success: false,
            error: "Invalid status"
          }, 400);
        }

        const result = await env.DB.prepare(
          `UPDATE partner_applications
           SET status = ?,
               reviewed_at = CURRENT_TIMESTAMP,
               reviewed_by = ?,
               updated_at = CURRENT_TIMESTAMP
           WHERE id = ?`
        ).bind(status, admin.uid, id).run();

        if (!result.meta || result.meta.changes === 0) {
          return json({
            success: false,
            error: "Partner application not found"
          }, 404);
        }

        return json({
          success: true,
          message: "Partner status updated",
          id,
          status
        });
      } catch (error) {
        return json({
          success: false,
          error: error.message === "Administrator access required"
            ? "Admin access denied"
            : "Unable to update partner status"
        }, error.message === "Administrator access required" ? 403 : 401);
      }
    }

    // PARTNER: Get own application
    if (
      path === "/api/partner/me" &&
      request.method === "GET"
    ) {
      try {
        if (!env.DB) {
          return json({ success: false, error: "Database is not configured" }, 500);
        }

        let user;

        try {
          user = await verifyFirebaseToken(request);
        } catch (error) {
          return json({ success: false, error: "Please sign in again" }, 401);
        }

        const partner = await env.DB.prepare(
          `SELECT id, full_name, email, status, created_at
           FROM partner_applications
           WHERE auth_uid = ? AND email = ?
           LIMIT 1`
        ).bind(user.uid, user.email).first();

        if (!partner) {
          return json({
            success: false,
            error: "No partner application was found for this account"
          }, 404);
        }

        return json({
          success: true,
          partner: {
            id: partner.id,
            fullName: partner.full_name,
            email: partner.email,
            status: partner.status,
            createdAt: partner.created_at
          },
          status: partner.status
        });
      } catch (error) {
        return json({
          success: false,
          error: "Unable to verify partner account"
        }, 500);
      }
    }

    // PARTNER: Submit application
    if (
      path === "/api/partner/applications" &&
      request.method === "POST"
    ) {
      try {
        if (!env.DB) {
          return json({ success: false, error: "Database is not configured" }, 500);
        }

        const contentType = request.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
          return json({
            success: false,
            error: "Content-Type must be application/json"
          }, 415);
        }

        const length = Number(request.headers.get("content-length") || 0);
        if (length > 16000) {
          return json({
            success: false,
            error: "Request is too large"
          }, 413);
        }

        let user;

        try {
          user = await verifyFirebaseToken(request);
        } catch (error) {
          return json({
            success: false,
            error: "Please sign in with your Firebase account again"
          }, 401);
        }

        const data = await request.json();

        const fullName = String(data.fullName || "").trim();
        const email = String(data.email || "").trim().toLowerCase();
        const country = String(data.country || "").trim();
        const socialProfile = String(data.socialProfile || "").trim();
        const contentCategory = String(data.contentCategory || "").trim();
        const rightsConfirmed = data.rightsConfirmed === true;

        if (email !== user.email) {
          return json({
            success: false,
            error: "Application email must match your signed-in account"
          }, 403);
        }

        if (
          fullName.length < 2 ||
          fullName.length > 100 ||
          !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
          email.length > 254
        ) {
          return json({
            success: false,
            error: "Please provide a valid name and email"
          }, 400);
        }

        if (
          country.length < 2 ||
          country.length > 100 ||
          socialProfile.length > 500 ||
          contentCategory.length < 2 ||
          contentCategory.length > 100
        ) {
          return json({
            success: false,
            error: "Please check the application fields"
          }, 400);
        }

        if (!rightsConfirmed) {
          return json({
            success: false,
            error: "Rights confirmation is required"
          }, 400);
        }

        const existing = await env.DB.prepare(
          `SELECT id, auth_uid, status
           FROM partner_applications
           WHERE email = ?
           LIMIT 1`
        ).bind(email).first();

        if (existing) {
          if (existing.auth_uid && existing.auth_uid !== user.uid) {
            return json({
              success: false,
              error: "An application already exists for this email"
            }, 409);
          }

          if (!existing.auth_uid) {
            await env.DB.prepare(
              `UPDATE partner_applications
               SET auth_uid = ?,
                   full_name = ?,
                   country = ?,
                   social_profile = ?,
                   content_category = ?,
                   rights_confirmed = 1,
                   updated_at = CURRENT_TIMESTAMP
               WHERE id = ? AND auth_uid IS NULL`
            ).bind(
              user.uid,
              fullName,
              country,
              socialProfile,
              contentCategory,
              existing.id
            ).run();
          }

          return json({
            success: true,
            message: "Your application already exists",
            status: existing.status,
            id: existing.id
          });
        }

        await env.DB.prepare(
          `INSERT INTO partner_applications
           (auth_uid, full_name, email, country, social_profile,
            content_category, rights_confirmed)
           VALUES (?, ?, ?, ?, ?, ?, 1)`
        ).bind(
          user.uid,
          fullName,
          email,
          country,
          socialProfile,
          contentCategory
        ).run();

        const application = await env.DB.prepare(
          `SELECT id, status
           FROM partner_applications
           WHERE auth_uid = ?
           LIMIT 1`
        ).bind(user.uid).first();

        return json({
          success: true,
          message: "Application submitted successfully",
          status: application?.status || "Pending",
          id: application?.id || null
        }, 201);

      } catch (error) {
        return json({
          success: false,
          error: "Unable to submit application"
        }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
