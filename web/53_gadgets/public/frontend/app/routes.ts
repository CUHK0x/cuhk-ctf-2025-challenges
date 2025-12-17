import { type RouteConfig, route } from "@react-router/dev/routes";

export default [
  route("/", "./Home.tsx"),
  route("/:id", "./whiteboard/Whiteboard.tsx"),
] satisfies RouteConfig;
