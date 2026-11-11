function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Backend health check
    if (url.pathname === "/api/health" && request.method === "GET") {
      return json({
        success: true,
        app: env.APP_NAME || "ViralDil",
        database: Boolean(env.DB),
        message: "ViralDil Worker is running"
      });
    }

    // Submit partner application
    if (
      url.pathname === "/api/partner/applications" &&
      request.method === "POST"
    ) {
      try {
        if (!env.DB) {
          return json({
            success: false,
            error: "Database is not configured"
          }, 500);
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

        const data = await request.json();

        const fullName = String(data.fullName || "").trim();
        const email = String(data.email || "").trim().toLowerCase();
        const country = String(data.country || "").trim();
        const socialProfile = String(data.socialProfile || "").trim();
        const contentCategory = String(data.contentCategory || "").trim();
        const rightsConfirmed = data.rightsConfirmed === true;

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
          country.length > 100 ||
          socialProfile.length > 500 ||
          contentCategory.length > 100
        ) {
          return json({
            success: false,
            error: "One or more fields are too long"
          }, 400);
        }

        if (!rightsConfirmed) {
          return json({
            success: false,
            error: "Rights confirmation is required"
          }, 400);
        }

        const existing = await env.DB.prepare(
          `SELECT id FROM partner_applications
           WHERE email = ?
           LIMIT 1`
        ).bind(email).first();

        if (existing) {
          return json({
            success: false,
            error: "An application already exists for this email"
          }, 409);
        }

        const result = await env.DB.prepare(
          `INSERT INTO partner_applications
           (full_name, email, country, social_profile,
            content_category, rights_confirmed)
           VALUES (?, ?, ?, ?, ?, 1)`
        ).bind(
          fullName,
          email,
          country,
          socialProfile,
          contentCategory
        ).run();

        return json({
          success: true,
          message: "Application submitted successfully",
          status: "Pending",
          id: result.meta?.last_row_id || null
        }, 201);

      } catch (error) {
        return json({
          success: false,
          error: "Unable to submit application"
        }, 500);
      }
    }

    // Serve website files
    return env.ASSETS.fetch(request);
  }
};
