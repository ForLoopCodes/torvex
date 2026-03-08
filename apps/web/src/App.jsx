// torvex web - root app with auth and chat
// manages login state and renders appropriate view

import React, { useState } from "react";
import Auth from "./views/Auth";
import Chat from "./views/Chat";

export default function App() {
  const [session, setSession] = useState(null);

  if (!session) return <Auth onAuth={setSession} />;
  return <Chat session={session} onLogout={() => setSession(null)} />;
}
