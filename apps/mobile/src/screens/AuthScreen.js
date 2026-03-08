// torvex mobile - wallet auth with pin vault
// seed phrase create/restore, pin encrypt, auto-unlock

import React, { useState, useEffect } from "react";
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  ScrollView,
  StyleSheet,
  Alert,
} from "react-native";
import { authenticate, generateMnemonic, validateMnemonic } from "../utils/api";
import {
  encryptVault,
  decryptVault,
  hasVault,
  clearVault,
  getDeviceId,
} from "../utils/vault";

export default function AuthScreen({ onAuth }) {
  const [phase, setPhase] = useState("start");
  const [mnemonic, setMnemonic] = useState("");
  const [pin, setPin] = useState("");
  const [generatedPhrase, setGeneratedPhrase] = useState("");
  const [error, setError] = useState("");
  const [vaultExists, setVaultExists] = useState(false);

  useEffect(() => {
    setVaultExists(hasVault());
  }, []);

  async function doAuth(phrase, userPin) {
    setError("");
    try {
      const session = await authenticate(phrase);
      session.deviceId = getDeviceId();
      encryptVault(userPin, phrase);
      onAuth(session);
    } catch (err) {
      setError(err.message);
    }
  }

  async function unlockVault() {
    if (!pin || pin.length < 4) return setError("pin must be at least 4 digits");
    try {
      const phrase = decryptVault(pin);
      if (!phrase) return setError("no saved wallet found");
      await doAuth(phrase, pin);
    } catch {
      setError("wrong pin or corrupted vault");
    }
  }

  function handleClearVault() {
    Alert.alert("clear wallet?", "this will remove your saved keys from this device.", [
      { text: "cancel", style: "cancel" },
      {
        text: "clear",
        style: "destructive",
        onPress: () => {
          clearVault();
          setVaultExists(false);
          setPhase("start");
        },
      },
    ]);
  }

  if (vaultExists && phase === "start") {
    return (
      <View style={s.container}>
        <Text style={s.logo}>torvex</Text>
        <Text style={s.tagline}>enter your pin to unlock</Text>
        <TextInput
          style={s.input}
          value={pin}
          onChangeText={(t) => setPin(t.replace(/\D/g, ""))}
          placeholder="pin code"
          placeholderTextColor="#6b6b80"
          keyboardType="numeric"
          secureTextEntry
          maxLength={8}
        />
        {!!error && <Text style={s.error}>{error}</Text>}
        <TouchableOpacity style={s.btn} onPress={unlockVault}>
          <Text style={s.btnText}>unlock</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={handleClearVault}>
          <Text style={s.link}>use different wallet</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (phase === "generated") {
    return (
      <ScrollView contentContainerStyle={s.container}>
        <Text style={s.logo}>torvex</Text>
        <Text style={s.tagline}>your new seed phrase</Text>
        <View style={s.seedBox}>
          {generatedPhrase.split(" ").map((word, i) => (
            <View key={i} style={s.seedWordWrap}>
              <Text style={s.seedNum}>{i + 1}.</Text>
              <Text style={s.seedWord}>{word}</Text>
            </View>
          ))}
        </View>
        <Text style={s.warning}>
          write this down. lose it and you lose access forever.
        </Text>
        <Text style={s.tagline}>set a pin to encrypt your keys</Text>
        <TextInput
          style={s.input}
          value={pin}
          onChangeText={(t) => setPin(t.replace(/\D/g, ""))}
          placeholder="pin code (4+ digits)"
          placeholderTextColor="#6b6b80"
          keyboardType="numeric"
          secureTextEntry
          maxLength={8}
        />
        {!!error && <Text style={s.error}>{error}</Text>}
        <TouchableOpacity
          style={s.btn}
          onPress={() => {
            if (pin.length < 4) return setError("pin must be at least 4 digits");
            doAuth(generatedPhrase, pin);
          }}
        >
          <Text style={s.btnText}>i saved it — sign in</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => setPhase("start")}>
          <Text style={s.link}>back</Text>
        </TouchableOpacity>
      </ScrollView>
    );
  }

  if (phase === "restore") {
    return (
      <ScrollView contentContainerStyle={s.container}>
        <Text style={s.logo}>torvex</Text>
        <Text style={s.tagline}>enter your 24-word seed phrase</Text>
        <TextInput
          style={[s.input, s.textArea]}
          value={mnemonic}
          onChangeText={(t) => setMnemonic(t.toLowerCase())}
          placeholder="word1 word2 word3 ... word24"
          placeholderTextColor="#6b6b80"
          multiline
          numberOfLines={4}
          autoCapitalize="none"
        />
        <Text style={s.tagline}>set a pin to encrypt your keys</Text>
        <TextInput
          style={s.input}
          value={pin}
          onChangeText={(t) => setPin(t.replace(/\D/g, ""))}
          placeholder="pin code (4+ digits)"
          placeholderTextColor="#6b6b80"
          keyboardType="numeric"
          secureTextEntry
          maxLength={8}
        />
        {!!error && <Text style={s.error}>{error}</Text>}
        <TouchableOpacity
          style={s.btn}
          onPress={() => {
            if (!validateMnemonic(mnemonic.trim()))
              return setError("invalid seed phrase");
            if (pin.length < 4) return setError("pin must be at least 4 digits");
            doAuth(mnemonic.trim(), pin);
          }}
        >
          <Text style={s.btnText}>sign in with seed</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => setPhase("start")}>
          <Text style={s.link}>back</Text>
        </TouchableOpacity>
      </ScrollView>
    );
  }

  return (
    <View style={s.container}>
      <Text style={s.logo}>torvex</Text>
      <Text style={s.tagline}>encrypted. anonymous. yours.</Text>
      <TouchableOpacity
        style={s.btn}
        onPress={() => {
          setGeneratedPhrase(generateMnemonic());
          setPhase("generated");
        }}
      >
        <Text style={s.btnText}>create new wallet</Text>
      </TouchableOpacity>
      <TouchableOpacity
        style={[s.btn, s.btnSecondary]}
        onPress={() => setPhase("restore")}
      >
        <Text style={[s.btnText, s.btnSecondaryText]}>restore from seed</Text>
      </TouchableOpacity>
      {!!error && <Text style={s.error}>{error}</Text>}
    </View>
  );
}

const s = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#0a0a0f",
    justifyContent: "center",
    alignItems: "center",
    padding: 24,
  },
  logo: {
    fontSize: 36,
    fontWeight: "800",
    color: "#7c5cfc",
    marginBottom: 8,
    letterSpacing: 2,
  },
  tagline: {
    color: "#6b6b80",
    fontSize: 14,
    marginBottom: 20,
    textAlign: "center",
  },
  input: {
    backgroundColor: "#12121a",
    borderWidth: 1,
    borderColor: "#1e1e2e",
    color: "#e4e4ef",
    padding: 14,
    borderRadius: 8,
    width: "100%",
    fontSize: 16,
    marginBottom: 12,
  },
  textArea: { minHeight: 100, textAlignVertical: "top" },
  btn: {
    backgroundColor: "#7c5cfc",
    paddingVertical: 14,
    paddingHorizontal: 24,
    borderRadius: 8,
    width: "100%",
    alignItems: "center",
    marginBottom: 12,
  },
  btnText: { color: "#fff", fontWeight: "700", fontSize: 16 },
  btnSecondary: { backgroundColor: "transparent", borderWidth: 1, borderColor: "#1e1e2e" },
  btnSecondaryText: { color: "#e4e4ef" },
  link: { color: "#7c5cfc", fontSize: 14, marginTop: 8 },
  error: { color: "#e05555", fontSize: 13, marginBottom: 12, textAlign: "center" },
  warning: {
    color: "#e05555",
    fontSize: 12,
    textAlign: "center",
    marginBottom: 16,
    paddingHorizontal: 8,
  },
  seedBox: {
    flexDirection: "row",
    flexWrap: "wrap",
    justifyContent: "center",
    gap: 8,
    marginBottom: 16,
    padding: 12,
    backgroundColor: "#12121a",
    borderRadius: 8,
    width: "100%",
  },
  seedWordWrap: { flexDirection: "row", gap: 4, minWidth: 80 },
  seedNum: { color: "#6b6b80", fontSize: 12 },
  seedWord: { color: "#e4e4ef", fontSize: 14, fontWeight: "600" },
});
