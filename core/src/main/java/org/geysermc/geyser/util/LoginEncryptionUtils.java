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
import org.geysermc.cumulus.form.CustomForm;
import org.geysermc.cumulus.form.ModalForm;
import org.geysermc.cumulus.form.SimpleForm;
import org.geysermc.cumulus.response.SimpleFormResponse;
import org.geysermc.cumulus.response.result.FormResponseResult;
import org.geysermc.cumulus.response.result.ValidFormResponseResult;
import org.geysermc.geyser.GeyserImpl;
import org.geysermc.geyser.configuration.GeyserConfiguration;
import org.geysermc.geyser.menu.SystemMenus;
import org.geysermc.geyser.session.GeyserSession;
import org.geysermc.geyser.session.auth.AuthData;
import org.geysermc.geyser.session.auth.BedrockClientData;
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
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

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
//
//            if (!validChain && !session.getGeyser().getConfig().isEnableProxyConnections()) {
//                session.disconnect(GeyserLocale.getLocaleStringLog("geyser.network.remote.invalid_xbox_account"));
//                return;
//            }
            JWSObject jwt = JWSObject.parse(certChainData.get(certChainData.size() - 1).asText());
            JsonNode payload = JSON_MAPPER.readTree(jwt.getPayload().toBytes());

//            if (payload.get("extraData").getNodeType() != JsonNodeType.OBJECT) {
//                throw new RuntimeException("AuthData was not found!");
//            }

            JsonNode extraData = payload.get("extraData");
            session.setAuthenticationData(new AuthData(
                    extraData.get("displayName").asText(),
                    UUID.fromString(extraData.get("identity").asText()),
                    UUID.fromString(extraData.get("identity").asText()).toString()
//                    certChainData, clientData
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
                        .title("Login")
                        .content("You need an account to login")
                        .button("Login")
                        .button("Register")
                        .button("Cancel")
                        .validResultHandler(response -> {
                            if (isPasswordAuthEnabled && response.clickedButtonId() == 0) {
                                session.setMicrosoftAccount(false);
                                loginForm(session);
                                return;
                            }
                            if (isPasswordAuthEnabled && response.clickedButtonId() == 1) {
                                session.setMicrosoftAccount(false);
                                registerForm(session);
                                return;
                            }

                            session.disconnect(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.disconnect", session.getLocale()));
                        })
                        .invalidResultHandler(() -> buildAndShowLoginWindow(session)));
    }

    public static void loginForm(GeyserSession session) {
        session.sendForm(CustomForm.builder()
                .title("Login")
                .label("Please enter your username and password")
                .input("Username", "steve", "")
                .input("Password", "SteveInMinecraft23", "")
                .invalidResultHandler(() -> loginForm(session))
                .validResultHandler((form, response) -> {
                    if (response.isClosed()) {
                        buildAndShowLoginWindow(session);
                        return;
                    }
                    if (!response.isCorrect()) {
                        ;
                        return;
                    }

                    String username = response.next();
                    String password = response.next();

                    if (!session.authenticate(username, password)) {
                        incorrectTryAgainForm(session, "Failed to authenticate, incorrect username or password", LoginEncryptionUtils::loginForm);
                        return;
                    }
                    assert username != null;

                    SystemMenus menus = new SystemMenus(username, session);
                    menus.main();
                })
        );
    }
    /**
     * Build a window that explains the user's credentials will be saved to the system.
     */
    public static void buildAndShowConsentWindow(GeyserSession session) {
        session.sendForm(
                SimpleForm.builder()
                        .translator(LoginEncryptionUtils::translate, session.getLocale())
                        .title("%gui.signIn")
                        .content("""
                                geyser.auth.login.save_token.warning

                                geyser.auth.login.save_token.proceed""")
                        .button("%gui.ok")
                        .button("%gui.decline")
                        .resultHandler(authenticateOrKickHandler(session))
        );
    }

    public static void buildAndShowTokenExpiredWindow(GeyserSession session) {
        session.sendForm(
                SimpleForm.builder()
                        .translator(LoginEncryptionUtils::translate, session.getLocale())
                        .title("geyser.auth.login.form.expired")
                        .content("""
                                geyser.auth.login.save_token.expired

                                geyser.auth.login.save_token.proceed""")
                        .button("%gui.ok")
                        .resultHandler(authenticateOrKickHandler(session))
        );
    }

    private static BiConsumer<SimpleForm, FormResponseResult<SimpleFormResponse>> authenticateOrKickHandler(GeyserSession session) {
        return (form, genericResult) -> {
            if (genericResult instanceof ValidFormResponseResult<SimpleFormResponse> result &&
                    result.response().clickedButtonId() == 0) {
                session.authenticateWithMicrosoftCode(true);
            } else {
                session.disconnect("%disconnect.quitting");
            }
        };
    }

    public static void buildAndShowLoginDetailsWindow(GeyserSession session) {
        session.sendForm(
                CustomForm.builder()
                        .translator(GeyserLocale::getPlayerLocaleString, session.getLocale())
                        .title("geyser.auth.login.form.details.title")
                        .label("geyser.auth.login.form.details.desc")
                        .input("geyser.auth.login.form.details.email", "account@geysermc.org", "")
                        .input("geyser.auth.login.form.details.pass", "123456", "")
                        .invalidResultHandler(() -> buildAndShowLoginDetailsWindow(session))
                        .closedResultHandler(() -> {
                            if (session.isMicrosoftAccount()) {
                                buildAndShowMicrosoftAuthenticationWindow(session);
                            } else {
                                buildAndShowLoginWindow(session);
                            }
                        })
                        .validResultHandler((response) -> session.authenticate(response.next(), response.next())));
    }

    public static void registerForm(GeyserSession session) {
        session.sendForm(CustomForm.builder()
                .title("Register")
                .label("Please enter your username and password")
                .input("Username", "", "")
                .input("Password", "", "")
                .invalidResultHandler(() -> registerForm(session))
                .validResultHandler((response) -> {
                    if (response.isClosed()) {
                        buildAndShowLoginWindow(session);
                        return;
                    }

                    String username = response.next();
                    String password = response.next();

                    assert username != null;
                    assert password != null;

                    if (username.matches("\\W")) {
                        incorrectTryAgainForm(session,
                                "Invalid username, you can only use letters, numbers, and underscores.",
                                LoginEncryptionUtils::registerForm);
                        return;
                    }

                    if (username.length() < 3 || username.length() > 16) {
                        incorrectTryAgainForm(session,
                                "Invalid username, must be between 3 and 16 characters.",
                                LoginEncryptionUtils::registerForm);
                        return;
                    }

                    if (LocalLoginUtil.hasUsername(username)) {
                        incorrectTryAgainForm(session,
                                "Username has been taken, please use another one.",
                                LoginEncryptionUtils::registerForm);
                        return;
                    }

                    LocalLoginUtil.insertLocally(username, password);
                    if (!session.authenticate(username, password)) {
                        throw new RuntimeException("Failed to authenticate after registering");
                    }
                })
        );
    }

    public static void incorrectTryAgainForm(GeyserSession session, String error, Consumer<GeyserSession> onCancel) {
        session.sendForm(SimpleForm.builder()
                .title(error)
                .content("Please try again")
                .button("Try again")
                .resultHandler((form, responseData) -> onCancel.accept(session))
        );
    }

//    public static void buildAndShowLoginDetailsWindow(GeyserSession session) {
//        session.sendForm(
//                CustomForm.builder()
//                        .translator(GeyserLocale::getPlayerLocaleString, session.getLocale())
//                        .title("geyser.auth.login.form.details.title")
//                        .label("geyser.auth.login.form.details.desc")
//                        .input("geyser.auth.login.form.details.email", "account@geysermc.org", "")
//                        .input("geyser.auth.login.form.details.pass", "123456", "")
//                        .responseHandler((form, responseData) -> {
//                            CustomFormResponse response = form.parseResponse(responseData);
//                            if (!response.isCorrect()) {
//                                buildAndShowLoginDetailsWindow(session);
//                                return;
//                            }
//
//                            session.authenticate(response.next(), response.next());
//                        }));
//    }

    /**
     * Prompts the user between either OAuth code login or manual password authentication
     */
//    public static void buildAndShowMicrosoftAuthenticationWindow(GeyserSession session) {
//        session.sendForm(
//                SimpleForm.builder()
//                        .translator(GeyserLocale::getPlayerLocaleString, session.getLocale())
//                        .title("geyser.auth.login.form.notice.btn_login.microsoft")
//                        .button("geyser.auth.login.method.browser")
//                        .button("geyser.auth.login.method.password")
//                        .button("geyser.auth.login.form.notice.btn_disconnect")
//                        .responseHandler((form, responseData) -> {
//                            SimpleFormResponse response = form.parseResponse(responseData);
//                            if (!response.isCorrect()) {
//                                buildAndShowLoginWindow(session);
//                                return;
//                            }
//
//                            if (response.getClickedButtonId() == 0) {
//                                session.authenticateWithMicrosoftCode();
//                            } else if (response.getClickedButtonId() == 1) {
//                                buildAndShowLoginDetailsWindow(session);
//                            } else {
//                                session.disconnect(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.disconnect", session.getLocale()));
//                            }
//                        }));
//    }
    public static void buildAndShowMicrosoftAuthenticationWindow(GeyserSession session) {
        session.sendForm(
                SimpleForm.builder()
                        .translator(GeyserLocale::getPlayerLocaleString, session.getLocale())
                        .title("geyser.auth.login.form.notice.btn_login.microsoft")
                        .button("geyser.auth.login.method.browser")
                        .button("geyser.auth.login.method.password")
                        .button("geyser.auth.login.form.notice.btn_disconnect")
                        .closedOrInvalidResultHandler(() -> buildAndShowLoginWindow(session))
                        .validResultHandler((response) -> {
                            if (response.clickedButtonId() == 0) {
                                session.authenticateWithMicrosoftCode();
                            } else if (response.clickedButtonId() == 1) {
                                buildAndShowLoginDetailsWindow(session);
                            } else {
                                session.disconnect(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.disconnect", session.getLocale()));
                            }
                        }));
    }

    /**
     * Shows the code that a user must input into their browser
     */
//    public static void buildAndShowMicrosoftCodeWindow(GeyserSession session, MsaAuthenticationService.MsCodeResponse msCode) {
//        session.sendForm(
//                ModalForm.builder()
//                        .title("%xbox.signin")
//                        .content("%xbox.signin.website\n%xbox.signin.url\n%xbox.signin.enterCode\n" + msCode.user_code)
//                        .button1("%gui.done")
//                        .button2("%menu.disconnect")
//                        .responseHandler((form, responseData) -> {
//                            ModalFormResponse response = form.parseResponse(responseData);
//                            if (!response.isCorrect()) {
//                                buildAndShowMicrosoftAuthenticationWindow(session);
//                                return;
//                            }
//
//                            if (response.getClickedButtonId() == 1) {
//                                session.disconnect(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.disconnect", session.getLocale()));
//                            }
//                        })
//        );
//    }
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
                        .closedOrInvalidResultHandler(() -> buildAndShowMicrosoftAuthenticationWindow(session))
                        .validResultHandler((response) -> {
                            if (response.clickedButtonId() == 1) {
                                session.disconnect(GeyserLocale.getPlayerLocaleString("geyser.auth.login.form.disconnect", session.getLocale()));
                            }
                        })
        );
    }

    /*
    This checks per line if there is something to be translated, and it skips Bedrock translation keys (%)
     */
    private static String translate(String key, String locale) {
        StringBuilder newValue = new StringBuilder();
        int previousIndex = 0;
        while (previousIndex < key.length()) {
            int nextIndex = key.indexOf('\n', previousIndex);
            int endIndex = nextIndex == -1 ? key.length() : nextIndex;

            // if there is more to this line than just a new line char
            if (endIndex - previousIndex > 1) {
                String substring = key.substring(previousIndex, endIndex);
                if (key.charAt(previousIndex) != '%') {
                    newValue.append(GeyserLocale.getPlayerLocaleString(substring, locale));
                } else {
                    newValue.append(substring);
                }
            }
            newValue.append('\n');

            previousIndex = endIndex + 1;
        }
        return newValue.toString();
    }
}
