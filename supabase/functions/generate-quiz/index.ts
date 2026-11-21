import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";

const allowedOrigins = (Deno.env.get("APP_ALLOWED_ORIGINS") ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

function corsHeaders(origin: string | null) {
  const allowed = origin && allowedOrigins.includes(origin) ? origin : "null";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

function jsonResponse(body: unknown, status: number, headers: Record<string, string>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, "Content-Type": "application/json" },
  });
}

serve(async (req) => {
  const origin = req.headers.get("origin");
  const headers = corsHeaders(origin);

  if (req.method === "OPTIONS") {
    if (origin && headers["Access-Control-Allow-Origin"] === "null") {
      return new Response(null, { status: 403, headers });
    }
    return new Response(null, { headers });
  }

  if (req.method !== "POST") {
    return jsonResponse({ error: "Méthode non autorisée" }, 405, headers);
  }

  if (origin && headers["Access-Control-Allow-Origin"] === "null") {
    return jsonResponse({ error: "Origine non autorisée" }, 403, headers);
  }

  try {
    const authorization = req.headers.get("Authorization");
    if (!authorization?.startsWith("Bearer ")) {
      return jsonResponse({ error: "Authentification requise" }, 401, headers);
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const aiApiKey = Deno.env.get("LOVABLE_API_KEY");
    if (!supabaseUrl || !supabaseAnonKey || !aiApiKey) {
      console.error("Required Edge Function environment variables are missing");
      return jsonResponse({ error: "Service momentanément indisponible" }, 503, headers);
    }

    const supabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authorization } },
      auth: { persistSession: false, autoRefreshToken: false },
    });

    const { data: authData, error: authError } = await supabase.auth.getUser();
    if (authError || !authData.user) {
      return jsonResponse({ error: "Session invalide" }, 401, headers);
    }

    const { data: isTeacher, error: roleError } = await supabase.rpc("has_role", {
      _user_id: authData.user.id,
      _role: "teacher",
    });
    const { data: isAdmin, error: adminRoleError } = await supabase.rpc("has_role", {
      _user_id: authData.user.id,
      _role: "admin",
    });
    if (roleError || adminRoleError) {
      console.error("Role verification failed");
      return jsonResponse({ error: "Vérification des droits impossible" }, 503, headers);
    }
    if (!isTeacher && !isAdmin) {
      return jsonResponse({ error: "Accès réservé aux enseignants" }, 403, headers);
    }

    const { data: quotaAllowed, error: quotaError } = await supabase.rpc("consume_ai_quiz_generation_quota");
    if (quotaError) {
      console.error("AI quota check failed");
      return jsonResponse({ error: "Limite IA temporairement indisponible" }, 503, headers);
    }
    if (!quotaAllowed) {
      return jsonResponse({ error: "Limite de générations atteinte. Réessayez plus tard." }, 429, headers);
    }

    const body = await req.json();
    const courseContent = typeof body.courseContent === "string" ? body.courseContent.trim() : "";
    const courseTitle = typeof body.courseTitle === "string" ? body.courseTitle.trim() : "";
    const numQuestions = Number(body.numQuestions ?? 5);
    const difficulty = body.difficulty ?? "medium";

    if (!courseContent || courseContent.length > 8000) {
      return jsonResponse({ error: "Le contenu doit contenir entre 1 et 8 000 caractères." }, 400, headers);
    }
    if (!Number.isInteger(numQuestions) || numQuestions < 1 || numQuestions > 20) {
      return jsonResponse({ error: "Le nombre de questions doit être compris entre 1 et 20." }, 400, headers);
    }
    if (!["easy", "medium", "hard"].includes(difficulty)) {
      return jsonResponse({ error: "Difficulté invalide." }, 400, headers);
    }
    if (courseTitle.length > 200) {
      return jsonResponse({ error: "Le titre du cours est trop long." }, 400, headers);
    }

    const difficultyMap: Record<string, string> = {
      easy: "faciles, testant la compréhension de base",
      medium: "de difficulté moyenne, testant la compréhension et l'application",
      hard: "difficiles, testant l'analyse et la réflexion approfondie",
    };

    const systemPrompt = `Tu es un expert en pédagogie et en création de QCM. Tu génères des questions claires à partir du cours fourni. Chaque question doit avoir exactement quatre options dont une seule est correcte. Réponds uniquement avec l'appel de fonction fourni.`;
    const userPrompt = `Génère ${numQuestions} questions ${difficultyMap[difficulty]} à partir du contenu suivant.

Titre : ${courseTitle || "Sans titre"}

Contenu :
${courseContent}`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${aiApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
        tools: [{
          type: "function",
          function: {
            name: "generate_questions",
            description: "Génère des questions QCM structurées",
            parameters: {
              type: "object",
              properties: {
                questions: {
                  type: "array",
                  minItems: numQuestions,
                  maxItems: numQuestions,
                  items: {
                    type: "object",
                    properties: {
                      text: { type: "string", minLength: 1, maxLength: 1000 },
                      explanation: { type: "string", maxLength: 1000 },
                      difficulty: { type: "string", enum: ["easy", "medium", "hard"] },
                      points: { type: "integer", minimum: 1, maximum: 3 },
                      options: {
                        type: "array",
                        minItems: 4,
                        maxItems: 4,
                        items: {
                          type: "object",
                          properties: {
                            text: { type: "string", minLength: 1, maxLength: 500 },
                            isCorrect: { type: "boolean" },
                          },
                          required: ["text", "isCorrect"],
                          additionalProperties: false,
                        },
                      },
                    },
                    required: ["text", "explanation", "difficulty", "points", "options"],
                    additionalProperties: false,
                  },
                },
              },
              required: ["questions"],
              additionalProperties: false,
            },
          },
        }],
        tool_choice: { type: "function", function: { name: "generate_questions" } },
      }),
    });

    if (response.status === 429) {
      return jsonResponse({ error: "Limite du fournisseur IA atteinte. Réessayez plus tard." }, 429, headers);
    }
    if (response.status === 402) {
      return jsonResponse({ error: "Crédits IA insuffisants." }, 402, headers);
    }
    if (!response.ok) {
      console.error("AI gateway returned status", response.status);
      return jsonResponse({ error: "Erreur du service IA" }, 502, headers);
    }

    const data = await response.json();
    const toolCall = data.choices?.[0]?.message?.tool_calls?.[0];
    if (!toolCall?.function?.arguments || typeof toolCall.function.arguments !== "string") {
      return jsonResponse({ error: "Réponse IA invalide" }, 502, headers);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(toolCall.function.arguments);
    } catch {
      return jsonResponse({ error: "Le format retourné par le service IA est invalide" }, 502, headers);
    }

    const questions = (parsed as { questions?: unknown })?.questions;
    if (!Array.isArray(questions) || questions.length !== numQuestions) {
      return jsonResponse({ error: "Le service IA a retourné un nombre de questions incorrect" }, 502, headers);
    }

    const valid = questions.every((q) =>
      q && typeof q === "object" &&
      typeof q.text === "string" && q.text.trim().length > 0 && q.text.length <= 1000 &&
      typeof q.explanation === "string" &&
      ["easy", "medium", "hard"].includes(q.difficulty) &&
      Number.isInteger(q.points) && q.points >= 1 && q.points <= 3 &&
      Array.isArray(q.options) && q.options.length === 4 &&
      q.options.every((o: unknown) =>
        o && typeof o === "object" &&
        typeof (o as { text?: unknown }).text === "string" &&
        typeof (o as { isCorrect?: unknown }).isCorrect === "boolean"
      ) &&
      q.options.filter((o: { isCorrect: boolean }) => o.isCorrect).length === 1
    );
    if (!valid) {
      return jsonResponse({ error: "Le service IA a retourné des questions mal formées" }, 502, headers);
    }

    return jsonResponse({ questions }, 200, headers);
  } catch (error) {
    console.error("generate-quiz failed:", error instanceof Error ? error.message : "Unknown error");
    return jsonResponse({ error: "Une erreur est survenue pendant la génération." }, 500, headers);
  }
});
