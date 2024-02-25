import { i18n } from "@lingui/core";
import { z } from "zod";
import { navigate } from "@/lib/router/router";
import { getApiError, getFieldErrors } from "@/shared/apiErrorListSchema";
import { accountManagementApi } from "@/lib/api/client";

export interface State {
  errors?: {
    email?: string[],
    password?: string[],
  };
  message?: string | null;
}

export const RegisterSchema = z.object({
  email: z.string().min(1, "Please enter your email").email("Please enter a valid email"),
  password: z.string().min(1, "Please enter your password"),
  firstName: z.string().min(1, "Please enter your first name"),
  lastName: z.string().min(1, "Please enter your last name"),
});

export async function register(_: State, formData: FormData): Promise<State> {
  const validatedFields = RegisterSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
    firstName: formData.get("firstName"),
    lastName: formData.get("lastName"),
  });

  if (!validatedFields.success) {
    // eslint-disable-next-line no-console
    console.log("validation errors", validatedFields.error.flatten().fieldErrors);
    return {
      errors: validatedFields.error.flatten().fieldErrors,
      message: i18n.t("Missing Fields. Failed to register."),
    };
  }

  const { email, password } = validatedFields.data;

  try {
    const result = await accountManagementApi.POST("/api/auth/register", {
      body: {
        email,
        password,
        // firstName,
        // lastName,
      },
    });

    if (result.response.ok) {
      navigate("/register/success");
      return {};
    }

    const apiError = getApiError(result);

    return {
      message: apiError.title,
      errors: getFieldErrors(apiError.Errors),
    };
  }
  catch (e) {
    return {
      message: i18n.t("Server error: Failed register."),
    };
  }
}
