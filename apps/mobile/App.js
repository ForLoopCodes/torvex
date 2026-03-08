// torvex mobile - main app entry point
// auth gate, chat, and qr scanner routing

import React, { useState } from "react";
import { StatusBar } from "react-native";
import AuthScreen from "./src/screens/AuthScreen";
import ChatScreen from "./src/screens/ChatScreen";
import ScanScreen from "./src/screens/ScanScreen";

export default function App() {
  const [session, setSession] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scannedPk, setScannedPk] = useState(null);

  if (!session) {
    return (
      <>
        <StatusBar barStyle="light-content" backgroundColor="#0a0a0f" />
        <AuthScreen onAuth={setSession} />
      </>
    );
  }

  if (scanning) {
    return (
      <ScanScreen
        onScan={(pk) => {
          setScannedPk(pk);
          setScanning(false);
        }}
        onClose={() => setScanning(false)}
      />
    );
  }

  return (
    <>
      <StatusBar barStyle="light-content" backgroundColor="#0a0a0f" />
      <ChatScreen
        session={session}
        scannedPk={scannedPk}
        onScan={() => setScanning(true)}
        onLogout={() => setSession(null)}
      />
    </>
  );
}
