/*
 * Copyright (c) 2019-2022 GeyserMC. http://geysermc.org
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author GeyserMC
 * @link https://github.com/GeyserMC/Geyser
 */

package org.geysermc.geyser.util;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.github.steveice10.mc.auth.service.MsaAuthenticationService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.shaded.json.JSONValue;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nukkitx.network.util.Preconditions;
import com.nukkitx.protocol.bedrock.packet.LoginPacket;
import com.nukkitx.protocol.bedrock.packet.ServerToClientHandshakePacket;
import com.nukkitx.protocol.bedrock.util.EncryptionUtils;
import org.geysermc.geyser.GeyserImpl;
import org.geysermc.geyser.configuration.GeyserConfiguration;
import org.geysermc.geyser.session.GeyserSession;
import org.geysermc.geyser.session.auth.AuthData;
import org.geysermc.geyser.session.auth.BedrockClientData;
import org.geysermc.cumulus.CustomForm;
import org.geysermc.cumulus.ModalForm;
import org.geysermc.cumulus.SimpleForm;
import org.geysermc.cumulus.response.CustomFormResponse;
import org.geysermc.cumulus.response.ModalFormResponse;
import org.geysermc.cumulus.response.SimpleFormResponse;
import org.geysermc.geyser.text.ChatColor;
import org.geysermc.geyser.text.GeyserLocale;

import javax.crypto.SecretKey;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

public class LoginEncryptionUtils {
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    private static boolean HAS_SENT_ENCRYPTION_MESSAGE = false;

    private static boolean validateChainData(JsonNode data) throws Exception {
        if (data.size() != 3) {
            return false;
        }

        ECPublicKey lastKey = null;
        boolean mojangSigned = false;
        Iterator<JsonNode> iterator = data.iterator();
        while (iterator.hasNext()) {
            JsonNode node = iterator.next();
            JWSObject jwt = JWSObject.parse(node.asText());

            // x509 cert is expected in every claim
            URI x5u = jwt.getHeader().getX509CertURL();
            if (x5u == null) {
                return false;
            }

            ECPublicKey expectedKey = EncryptionUtils.generateKey(jwt.getHeader().getX509CertURL().toString());
            // First key is self-signed
            if (lastKey == null) {
                lastKey = expectedKey;
            } else if (!lastKey.equals(expectedKey)) {
                return false;
            }

            if (!EncryptionUtils.verifyJwt(jwt, lastKey)) {
                return false;
            }

            if (mojangSigned) {
                return !iterator.hasNext();
            }

            if (lastKey.equals(EncryptionUtils.getMojangPublicKey())) {
                mojangSigned = true;
            }

            Object payload = JSONValue.parse(jwt.getPayload().toString());
            Preconditions.checkArgument(payload instanceof JSONObject, "Payload is not an object");

            Object identityPublicKey = ((JSONObject) payload).get("identityPublicKey");
            Preconditions.checkArgument(identityPublicKey instanceof String, "identityPublicKey node is missing in chain");
            lastKey = EncryptionUtils.generateKey((String) identityPublicKey);
        }

        return mojangSigned;
    }

    public static void encryptPlayerConnection(GeyserSession session, LoginPacket loginPacket) {
        JsonNode certData;
        try {
            certData = JSON_MAPPER.readTree(loginPacket.getChainData().toByteArray());
        } catch (IOException ex) {
            throw new RuntimeException("Certificate JSON can not be read.");
        }

        JsonNode certChainData = certData.get("chain");
        if (certChainData.getNodeType() != JsonNodeType.ARRAY) {
            throw new RuntimeException("Certificate data is not valid");
        }

        encryptConnectionWithCert(session, loginPacket.getSkinData().toString(), certChainData);
    }

    private static void encryptConnectionWithCert(GeyserSession session, String clientData, JsonNode certChainData) {
        try {
            GeyserImpl geyser = session.getGeyser();

//            boolean validChain = validateChainData(certChainData);
//
//            geyser.getLogger().debug(String.format("Is player data valid? %s", validChain));

//            if (!validChain && !session.getGeyser().getConfig().isEnableProxyConnections()) {
//                session.disconnect(GeyserLocale.getLocaleStringLog("geyser.network.remote.invalid_xbox_account"));
//                return;
//            }
            JWSObject jwt = JWSObject.parse(certChainData.get(certChainData.size() - 1).asText());
            JsonNode payload = JSON_MAPPER.readTree(jwt.getPayload().toBytes());
            System.out.println(payload);
//
//            if (payload.get("extraData").getNodeType() != JsonNodeType.OBJECT) {
//                throw new RuntimeException("AuthData was not found!");
//            }

            JsonNode extraData = payload.get("extraData");
            System.out.println("data: " + extraData);
            session.setAuthenticationData(new AuthData(
                    extraData.get("displayName").asText(),
                    UUID.fromString(extraData.get("identity").asText()),
                    UUID.fromString(extraData.get("identity").asText()).toString()
            ));

            session.setCertChainData(certChainData);

            if (payload.get("identityPublicKey").getNodeType() != JsonNodeType.STRING) {
                throw new RuntimeException("Identity Public Key was not found!");
            }

            ECPublicKey identityPublicKey = EncryptionUtils.generateKey(payload.get("identityPublicKey").textValue());
            JWSObject clientJwt = JWSObject.parse(clientData);
            EncryptionUtils.verifyJwt(clientJwt, identityPublicKey);

            JsonNode clientDataJson = JSON_MAPPER.readTree(clientJwt.getPayload().toBytes());
            BedrockClientData data = JSON_MAPPER.convertValue(clientDataJson, BedrockClientData.class);
            data.setOriginalString(clientData);
            session.setClientData(data);

            if (EncryptionUtils.canUseEncryption()) {
                try {
                    LoginEncryptionUtils.startEncryptionHandshake(session, identityPublicKey, clientDataJson);
                } catch (Throwable e) {
                    // An error can be thrown on older Java 8 versions about an invalid key
                    if (geyser.getConfig().isDebugMode()) {
                        e.printStackTrace();
                    }

                    sendEncryptionFailedMessage(geyser);
                }
            } else {
                sendEncryptionFailedMessage(geyser);
            }
        } catch (Exception ex) {
            session.disconnect("disconnectionScreen.internalError.cantConnect");
            throw new RuntimeException("Unable to complete login", ex);
        }
    }

    private static void startEncryptionHandshake(GeyserSession session, PublicKey key, JsonNode clientData) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair serverKeyPair = generator.generateKeyPair();

        byte[] token = EncryptionUtils.generateRandomToken();
        SecretKey encryptionKey = EncryptionUtils.getSecretKey(serverKeyPair.getPrivate(), key, token);
        session.getUpstream().getSession().enableEncryption(encryptionKey);

        ServerToClientHandshakePacket packet = new ServerToClientHandshakePacket();
        packet.setJwt(getHandshakeJwt(serverKeyPair, token, clientData).serialize());
        session.sendUpstreamPacketImmediately(packet);
    }

    public static JWSObject getHandshakeJwt(KeyPair serverKeyPair, byte[] token, JsonNode clientData) throws LoginException {
        // Education has a TenantID
        if (!clientData.has("TenantId")) {
            throw new LoginException("No TenantId found from client");
        }

        String tenantId = clientData.get("TenantId").asText();

        // Lookup a signed token for the tenant
        if (!TokenManager.INSTANCE.getTokenMap().containsKey(tenantId)) {
            throw new LoginException("Unknown Tenant tried to connect: " + tenantId);
        }

        Map<String, String> claims = Map.of("signedToken",
                TokenManager.INSTANCE.getTokenMap().get(tenantId).getSignedToken());

        try {
            return createHandshakeJwt(serverKeyPair, token, claims);
        } catch (JOSEException e) {
            throw new LoginException(e.toString());
        }
    }

    protected static JWSObject createHandshakeJwt(KeyPair serverKeyPair, byte[] token, Map<String, String> claims) throws JOSEException {
        URI x5u = URI.create(Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded()));

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        claimsBuilder.claim("salt", Base64.getEncoder().encodeToString(token));

        for (Map.Entry<String, String> claim : claims.entrySet()) {
            claimsBuilder.claim(claim.getKey(), claim.getValue());
        }

        SignedJWT jwt = new SignedJWT((new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.ES384)).x509CertURL(x5u).build(),
                claimsBuilder.build());
        EncryptionUtils.signJwt(jwt, (ECPrivateKey) serverKeyPair.getPrivate());
        return jwt;
    }

    private static void sendEncryptionFailedMessage(GeyserImpl geyser) {
        if (!HAS_SENT_ENCRYPTION_MESSAGE) {
            geyser.getLogger().warning(GeyserLocale.getLocaleStringLog("geyser.network.encryption.line_1"));
            geyser.getLogger().warning(GeyserLocale.getLocaleStringLog("geyser.network.encryption.line_2", "https://geysermc.org/supported_java"));
            HAS_SENT_ENCRYPTION_MESSAGE = true;
        }
    }

    public static void buildAndShowLoginWindow(GeyserSession session) {
        if (session.isLoggedIn()) {
            // Can happen if a window is cancelled during dimension switch
            return;
        }

        // Set DoDaylightCycle to false so the time doesn't accelerate while we're here
        session.setDaylightCycle(false);

        GeyserConfiguration config = session.getGeyser().getConfig();
        boolean isPasswordAuthEnabled = config.getRemote().isPasswordAuthentication();

        session.sendForm(
                SimpleForm.builder()
                        .translator(GeyserLocale::getPlayerLocaleString, session.getLocale())
                        .title("geyser.auth.login.form.notice.title")
                        .content("geyser.auth.login.form.notice.desc")
                        .optionalButton("geyser.auth.login.form.notice.btn_login.mojang", isPasswordAuthEnabled)
                        .button("geyser.auth.login.form.notice.btn_login.microsoft")
                        .button("geyser.auth.login.form.notice.btn_disconnect")
                        .responseHandler((form, responseData) -> {
                            SimpleFormResponse response = form.parseResponse(responseData);
                            if (!response.isCorrect()) {
                                buildAndShowLoginWindow(session);
                                return;
                            }

                            if (isPasswordAuthEnabled && response.getClickedButtonId() == 0) {
                                session.setMicrosoftAccount(false);
                                buildAndShowLoginDetailsWindow(session);
                                return;
                            }

                            if (isPasswordAuthEnabled && response.getClickedButtonId() == 1) {
                                session.setMicrosoftAccount(true);
                                buildAndShowMicrosoftAuthenticationWindow(session);
                                return;
                            }

                            if (response.getClickedButtonId() == 0) {
                                // Just show the OAuth code
                                session.authenticateWithMicrosoftCode();
                                return;
                            }

                            session.disconnect(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.disconnect", session.getLocale()));
                        }));
    }

    /**
     * Build a window that explains the user's credentials will be saved to the system.
     */
    public static void buildAndShowConsentWindow(GeyserSession session) {
        String locale = session.getLocale();
        session.sendForm(
                SimpleForm.builder()
                        .title("%gui.signIn")
                        .content(GeyserLocale.getPlayerLocaleString("geyser.auth.login.save_token.warning", locale) +
                                "\n\n" +
                                GeyserLocale.getPlayerLocaleString("geyser.auth.login.save_token.proceed", locale))
                        .button("%gui.ok")
                        .button("%gui.decline")
                        .responseHandler((form, responseData) -> {
                            SimpleFormResponse response = form.parseResponse(responseData);
                            if (response.isCorrect() && response.getClickedButtonId() == 0) {
                                session.authenticateWithMicrosoftCode(true);
                            } else {
                                session.disconnect("%disconnect.quitting");
                            }
                        }));
    }

    public static void buildAndShowTokenExpiredWindow(GeyserSession session) {
        String locale = session.getLocale();
        session.sendForm(
                SimpleForm.builder()
                        .title(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.expired", locale))
                        .content(GeyserLocale.getPlayerLocaleString("geyser.auth.login.save_token.expired", locale) +
                                "\n\n" +
                                GeyserLocale.getPlayerLocaleString("geyser.auth.login.save_token.proceed", locale))
                        .button("%gui.ok")
                        .responseHandler((form, responseData) -> {
                            SimpleFormResponse response = form.parseResponse(responseData);
                            if (response.isCorrect()) {
                                session.authenticateWithMicrosoftCode(true);
                            } else {
                                session.disconnect("%disconnect.quitting");
                            }
                        }));
    }

    public static void buildAndShowLoginDetailsWindow(GeyserSession session) {
        session.sendForm(
                CustomForm.builder()
                        .translator(GeyserLocale::getPlayerLocaleString, session.getLocale())
                        .title("geyser.auth.login.form.details.title")
                        .label("geyser.auth.login.form.details.desc")
                        .input("geyser.auth.login.form.details.email", "account@geysermc.org", "")
                        .input("geyser.auth.login.form.details.pass", "123456", "")
                        .responseHandler((form, responseData) -> {
                            CustomFormResponse response = form.parseResponse(responseData);
                            if (!response.isCorrect()) {
                                buildAndShowLoginDetailsWindow(session);
                                return;
                            }

                            session.authenticate(response.next(), response.next());
                        }));
    }

    /**
     * Prompts the user between either OAuth code login or manual password authentication
     */
    public static void buildAndShowMicrosoftAuthenticationWindow(GeyserSession session) {
        session.sendForm(
                SimpleForm.builder()
                        .translator(GeyserLocale::getPlayerLocaleString, session.getLocale())
                        .title("geyser.auth.login.form.notice.btn_login.microsoft")
                        .button("geyser.auth.login.method.browser")
                        .button("geyser.auth.login.method.password")
                        .button("geyser.auth.login.form.notice.btn_disconnect")
                        .responseHandler((form, responseData) -> {
                            SimpleFormResponse response = form.parseResponse(responseData);
                            if (!response.isCorrect()) {
                                buildAndShowLoginWindow(session);
                                return;
                            }

                            if (response.getClickedButtonId() == 0) {
                                session.authenticateWithMicrosoftCode();
                            } else if (response.getClickedButtonId() == 1) {
                                buildAndShowLoginDetailsWindow(session);
                            } else {
                                session.disconnect(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.disconnect", session.getLocale()));
                            }
                        }));
    }

    /**
     * Shows the code that a user must input into their browser
     */
    public static void buildAndShowMicrosoftCodeWindow(GeyserSession session, MsaAuthenticationService.MsCodeResponse msCode) {
        StringBuilder message = new StringBuilder("%xbox.signin.website\n")
                .append(ChatColor.AQUA)
                .append("%xbox.signin.url")
                .append(ChatColor.RESET)
                .append("\n%xbox.signin.enterCode\n")
                .append(ChatColor.GREEN)
                .append(msCode.user_code);
        int timeout = session.getGeyser().getConfig().getPendingAuthenticationTimeout();
        if (timeout != 0) {
            message.append("\n\n")
                    .append(ChatColor.RESET)
                    .append(GeyserLocale.getPlayerLocaleString("geyser.auth.login.timeout", session.getLocale(), String.valueOf(timeout)));
        }
        session.sendForm(
                ModalForm.builder()
                        .title("%xbox.signin")
                        .content(message.toString())
                        .button1("%gui.done")
                        .button2("%menu.disconnect")
                        .responseHandler((form, responseData) -> {
                            ModalFormResponse response = form.parseResponse(responseData);
                            if (!response.isCorrect()) {
                                buildAndShowMicrosoftAuthenticationWindow(session);
                                return;
                            }

                            if (response.getClickedButtonId() == 1) {
                                session.disconnect(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.disconnect", session.getLocale()));
                            }
                        })
        );
    }
}
