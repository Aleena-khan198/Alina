import { NextResponse } from "next/server";
import {
  JWT_ACTIVE_COOKIE,
  JWT_COOKIE_NAME,
  clearedJwtCookieOptions,
  isValidAdminJwt,
} from "@/lib/jwt/init";

/**
 * Protect /admin/* except /admin/login.
 * Requires a valid JWT cookie + active session flag (cleared on sign-out).
 *
 * @param {import('next/server').NextRequest} request
 */
export async function proxy(request) {
  const { pathname } = request.nextUrl;

  if (!pathname.startsWith("/admin")) {
    return NextResponse.next();
  }

  const isLogin =
    pathname === "/admin/login" || pathname.startsWith("/admin/login/");
  const token = request.cookies.get(JWT_COOKIE_NAME)?.value;
  const active = request.cookies.get(JWT_ACTIVE_COOKIE)?.value === "1";
  const authenticated = active && (await isValidAdminJwt(token));

  if (isLogin) {
    if (authenticated) {
      return NextResponse.redirect(new URL("/admin", request.url));
    }
    return NextResponse.next();
  }

  if (!authenticated) {
    const loginUrl = new URL("/admin/login", request.url);
    loginUrl.searchParams.set("next", pathname);
    const response = NextResponse.redirect(loginUrl);
    const cleared = clearedJwtCookieOptions();
    response.cookies.set(JWT_COOKIE_NAME, "", cleared);
    response.cookies.set(JWT_ACTIVE_COOKIE, "", cleared);
    return response;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/admin", "/admin/:path*"],
};
