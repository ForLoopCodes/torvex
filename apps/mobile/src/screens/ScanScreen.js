// torvex mobile - qr code scanner for pubkey exchange
// camera-based contact addition via base58 pubkey scan

import React, { useState, useEffect } from "react";
import { View, Text, TouchableOpacity, StyleSheet, Alert } from "react-native";
import {
  Camera,
  useCameraDevice,
  useCodeScanner,
} from "react-native-vision-camera";

export default function ScanScreen({ onScan, onClose }) {
  const [hasPermission, setHasPermission] = useState(false);
  const device = useCameraDevice("back");

  useEffect(() => {
    Camera.requestCameraPermission().then((status) => {
      setHasPermission(status === "granted");
    });
  }, []);

  const codeScanner = useCodeScanner({
    codeTypes: ["qr"],
    onCodeScanned: (codes) => {
      const value = codes[0]?.value;
      if (!value) return;
      const pk = value.trim();
      if (/^[1-9A-HJ-NP-Za-km-z]{32,64}$/.test(pk)) {
        onScan(pk);
      } else {
        Alert.alert(
          "invalid qr",
          "this qr code does not contain a valid pubkey",
        );
      }
    },
  });

  if (!hasPermission) {
    return (
      <View style={s.container}>
        <Text style={s.text}>camera permission required</Text>
        <TouchableOpacity style={s.btn} onPress={onClose}>
          <Text style={s.btnText}>close</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (!device) {
    return (
      <View style={s.container}>
        <Text style={s.text}>no camera found</Text>
        <TouchableOpacity style={s.btn} onPress={onClose}>
          <Text style={s.btnText}>close</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View style={s.container}>
      <Camera
        style={StyleSheet.absoluteFill}
        device={device}
        isActive={true}
        codeScanner={codeScanner}
      />
      <View style={s.overlay}>
        <Text style={s.overlayText}>scan a torvex pubkey qr code</Text>
        <TouchableOpacity style={s.closeBtn} onPress={onClose}>
          <Text style={s.closeBtnText}>✕</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#0a0a0f",
    justifyContent: "center",
    alignItems: "center",
  },
  text: { color: "#6b6b80", fontSize: 16, marginBottom: 16 },
  btn: {
    backgroundColor: "#7c5cfc",
    paddingVertical: 12,
    paddingHorizontal: 24,
    borderRadius: 8,
  },
  btnText: { color: "#fff", fontWeight: "700" },
  overlay: {
    position: "absolute",
    bottom: 0,
    left: 0,
    right: 0,
    padding: 24,
    paddingBottom: 48,
    backgroundColor: "rgba(10, 10, 15, 0.8)",
    alignItems: "center",
  },
  overlayText: { color: "#e4e4ef", fontSize: 14, marginBottom: 16 },
  closeBtn: {
    backgroundColor: "#e05555",
    width: 44,
    height: 44,
    borderRadius: 22,
    justifyContent: "center",
    alignItems: "center",
  },
  closeBtnText: { color: "#fff", fontSize: 18, fontWeight: "700" },
});
