import { useState } from "react";
import CryptoJS from "crypto-js";

// XOR two hex strings
function xorHexStrings(hexA, hexB) {
  const aBytes = hexA.match(/.{1,2}/g)?.map(h => parseInt(h, 16)) || [];
  const bBytes = hexB.match(/.{1,2}/g)?.map(h => parseInt(h, 16)) || [];
  const out = [];
  for (let i = 0; i < Math.max(aBytes.length, bBytes.length); i++) {
    const av = aBytes[i % aBytes.length] || 0;
    const bv = bBytes[i % bBytes.length] || 0;
    out.push((av ^ bv).toString(16).padStart(2, "0"));
  }
  return out.join("");
}

// Simplified key generation logic
function genKeyJS(password) {
  if (!password || typeof password !== "string" || !password.trim()) {
    throw new Error("Password must be a non-empty string");
  }

  try {
    // Use SHA-256 for simpler, reliable key derivation
    const h1 = CryptoJS.SHA256(password).toString();
    const salt = CryptoJS.lib.WordArray.random(16).toString();
    const key = CryptoJS.PBKDF2(password, salt, {
      keySize: 256 / 32,
      iterations: 1000,
      hasher: CryptoJS.algo.SHA256,
    });
    const finalKeyBase64 = CryptoJS.enc.Base64.stringify(key);
    const finalKeyHex = CryptoJS.enc.Hex.stringify(key);
    return { finalKeyHex, finalKeyBase64 };
  } catch (e) {
    throw new Error(`Key generation failed: ${e.message}`);
  }
}

// AES Encryption with derived key
function aesEncryptWithDerivedKey(plaintext, derivedKeyBase64) {
  if (!plaintext || typeof plaintext !== "string" || !plaintext.trim()) {
    throw new Error("Plaintext must be a non-empty string");
  }
  if (!derivedKeyBase64 || typeof derivedKeyBase64 !== "string") {
    throw new Error("Derived key must be a non-empty string");
  }

  try {
    const keyBytes = CryptoJS.SHA256(derivedKeyBase64);
    const iv = CryptoJS.lib.WordArray.random(16); // Use random IV for security
    const cipherObj = CryptoJS.AES.encrypt(plaintext, keyBytes, {
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
      iv: iv,
    });
    // Prepend IV (in Base64) to ciphertext for decryption
    const ivBase64 = CryptoJS.enc.Base64.stringify(iv);
    return `${ivBase64}:${cipherObj.toString()}`;
  } catch (e) {
    throw new Error(`Encryption failed: ${e.message}`);
  }
}

// AES Decryption with derived key
function aesDecryptWithDerivedKey(ciphertextWithIV, derivedKeyBase64) {
  if (!ciphertextWithIV || typeof ciphertextWithIV !== "string" || !ciphertextWithIV.trim()) {
    throw new Error("Ciphertext must be a non-empty string");
  }
  if (!derivedKeyBase64 || typeof derivedKeyBase64 !== "string") {
    throw new Error("Derived key must be a non-empty string");
  }

  try {
    // Split IV and ciphertext
    const [ivBase64, ciphertext] = ciphertextWithIV.split(":");
    if (!ivBase64 || !ciphertext) {
      throw new Error("Invalid ciphertext format (missing IV)");
    }
    const keyBytes = CryptoJS.SHA256(derivedKeyBase64);
    const iv = CryptoJS.enc.Base64.parse(ivBase64);
    const bytes = CryptoJS.AES.decrypt(ciphertext, keyBytes, {
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
      iv: iv,
    });
    const decrypted = CryptoJS.enc.Utf8.stringify(bytes);
    if (!decrypted) {
      return "(invalid UTF-8)";
    }
    return decrypted;
  } catch (e) {
    throw new Error(`Decryption failed: ${e.message}`);
  }
}

export default function HomePage() {
  const [data, setData] = useState("");
  const [key, setKey] = useState("");
  const [generatedKey, setGeneratedKey] = useState("");
  const [cipher, setCipher] = useState("");
  const [result, setResult] = useState("");
  const [status, setStatus] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleGenerate = () => {
    setIsLoading(true);
    setStatus("Generating key...");
    try {
      if (!key.trim()) {
        setStatus("Error: Key field cannot be empty");
        return;
      }
      const { finalKeyBase64 } = genKeyJS(key);
      setGeneratedKey(finalKeyBase64);
      setStatus("Key generated successfully");
    } catch (e) {
      setStatus(`Error generating key: ${e.message}`);
      console.error("Key generation error:", e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleEncrypt = () => {
    setIsLoading(true);
    try {
      if (!data.trim()) {
        setStatus("Error: Data field cannot be empty");
        return;
      }
      if (!key.trim()) {
        setStatus("Error: Key field cannot be empty");
        return;
      }
      if (!generatedKey) {
        const { finalKeyBase64 } = genKeyJS(key);
        setGeneratedKey(finalKeyBase64);
      }
      const ct = aesEncryptWithDerivedKey(data, generatedKey);
      setCipher(ct);
      setResult("");
      setStatus("Encrypted successfully");
    } catch (e) {
      setStatus(`Encryption error: ${e.message}`);
      console.error("Encryption error:", e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDecrypt = () => {
    setIsLoading(true);
    try {
      if (!cipher.trim()) {
        setStatus("Error: Ciphertext field cannot be empty");
        return;
      }
      if (!key.trim()) {
        setStatus("Error: Key field cannot be empty");
        return;
      }
      if (!generatedKey) {
        const { finalKeyBase64 } = genKeyJS(key);
        setGeneratedKey(finalKeyBase64);
      }
      const pt = aesDecryptWithDerivedKey(cipher, generatedKey);
      setResult(pt);
      setStatus(pt === "(invalid UTF-8)" ? "Decryption failed: Invalid data" : "Decrypted successfully");
    } catch (e) {
      setStatus(`Decryption error: ${e.message}`);
      console.error("Decryption error:", e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleReset = () => {
    setData("");
    setKey("");
    setGeneratedKey("");
    setCipher("");
    setResult("");
    setStatus("Fields reset");
    setIsLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 flex flex-col items-center p-4 sm:p-8">
      <div className="w-full max-w-2xl">
        <h1 className="text-4xl font-bold text-center mb-2">CipherX</h1>
        <p className="text-center text-gray-400 mb-8">
          Next-gen key generator & encryptor
        </p>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium mb-1">Enter Data</label>
            <textarea
              value={data}
              onChange={(e) => setData(e.target.value)}
              rows={4}
              className="w-full p-3 bg-gray-800 border border-gray-700 rounded-md text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Type your message here..."
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Enter Key</label>
            <div className="flex gap-2">
              <input
                value={key}
                onChange={(e) => setKey(e.target.value)}
                className="flex-1 p-3 bg-gray-800 border border-gray-700 rounded-md text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter your key..."
              />
              <button
                onClick={handleGenerate}
                disabled={isLoading}
                className={`px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 ${isLoading ? "opacity-50 cursor-not-allowed" : ""}`}
              >
                {isLoading ? "Generating..." : "Generate Key"}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">
              Generated Key (Base64)
            </label>
            <textarea
              readOnly
              value={generatedKey}
              rows={2}
              className="w-full p-3 bg-gray-800 border border-gray-700 rounded-md text-gray-100"
              placeholder="Generated key will appear here..."
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Ciphertext</label>
            <textarea
              readOnly
              value={cipher}
              rows={4}
              className="w-full p-3 bg-gray-800 border border-gray-700 rounded-md text-gray-100"
              placeholder="Encrypted text will appear here..."
            />
            <div className="flex gap-2 mt-2">
              <button
                onClick={handleEncrypt}
                disabled={isLoading}
                className={`flex-1 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 ${isLoading ? "opacity-50 cursor-not-allowed" : ""}`}
              >
                {isLoading ? "Encrypting..." : "Encrypt"}
              </button>
              <button
                onClick={handleDecrypt}
                disabled={isLoading}
                className={`flex-1 px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-purple-500 ${isLoading ? "opacity-50 cursor-not-allowed" : ""}`}
              >
                {isLoading ? "Decrypting..." : "Decrypt"}
              </button>
              <button
                onClick={handleReset}
                disabled={isLoading}
                className={`flex-1 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 ${isLoading ? "opacity-50 cursor-not-allowed" : ""}`}
              >
                Reset
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Decrypted</label>
            <textarea
              readOnly
              value={result}
              rows={4}
              className="w-full p-3 bg-gray-800 border border-gray-700 rounded-md text-gray-100"
              placeholder="Decrypted text will appear here..."
            />
          </div>

          <p
            className={`text-sm ${status.includes("Error") || status.includes("failed") ? "text-red-400" : "text-green-400"}`}
          >
            {status || "Ready"}
          </p>

          <p className="text-sm text-gray-400 text-center mt-8">
            © 2025 CipherX. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
}
