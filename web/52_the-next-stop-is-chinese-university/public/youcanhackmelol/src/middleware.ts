import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export async function middleware(request: NextRequest) {
  try {
    const formData = await request.formData();
    const username = formData.get("username");
    const password = formData.get("password");
    // If the user is trying to access a protected route and is not authenticated
    if (
      username !== process.env.USERNAME ||
      password !== process.env.PASSWORD
    ) {
      const loginUrl = new URL("/", request.url);
      return NextResponse.redirect(loginUrl);
    }

    return NextResponse.next();
  } catch {
    // If the user is trying to access a protected route and is not authenticated
    const loginUrl = new URL("/", request.url);
    return NextResponse.redirect(loginUrl);
  }
}

export const config = {
  matcher: ["/secret/:path*"],
};
