/*
 * Copyright (c) 2019-2020 GeyserMC. http://geysermc.org
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

package org.geysermc.connector.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.steveice10.mc.protocol.data.game.scoreboard.TeamColor;
import com.github.steveice10.mc.protocol.data.message.ChatColor;
import com.github.steveice10.mc.protocol.data.message.ChatFormat;
import com.github.steveice10.mc.protocol.data.message.Message;
import com.github.steveice10.mc.protocol.data.message.TranslationMessage;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.io.InputStream;
import java.util.*;

public class MessageUtils {
    private static final HashMap<String, String> LANG_MAPPINGS = new HashMap<>();

    static {
        /* Load the language mappings */
        InputStream stream = Toolbox.getResource("mappings/lang.json");
        JsonNode lang;
        try {
            lang = Toolbox.JSON_MAPPER.readTree(stream);
        } catch (Exception e) {
            throw new AssertionError("Unable to load Java lang mappings", e);
        }

        Iterator<Map.Entry<String, JsonNode>> langIterator = lang.fields();
        while (langIterator.hasNext()) {
            Map.Entry<String, JsonNode> entry = langIterator.next();
            LANG_MAPPINGS.put(entry.getKey(), entry.getValue().asText());
        }
    }

    public static List<String> getTranslationParams(Message[] messages) {
        List<String> strings = new ArrayList<>();
        for (Message message : messages) {
            if (message instanceof TranslationMessage) {
                TranslationMessage translation = (TranslationMessage) message;

                String builder = "%" + translation.getTranslationKey();
                strings.add(builder);

                if (translation.getTranslationKey().equals("commands.gamemode.success.other")) {
                    strings.add("");
                }

                if (translation.getTranslationKey().equals("command.context.here")) {
                    strings.add(" - no permission or invalid command!");
                }

                strings.addAll(getTranslationParams(translation.getTranslationParams()));
            } else {
                String builder = getFormat(message.getStyle().getFormats()) +
                        getColor(message.getStyle().getColor()) +
                        getBedrockMessage(message);
                strings.add(builder);
            }
        }

        return strings;
    }

    public static String getTranslationText(TranslationMessage message) {
        return getFormat(message.getStyle().getFormats()) + getColor(message.getStyle().getColor())
                + "%" + message.getTranslationKey();
    }

    public static String getBedrockMessageWithTranslate(Message message, boolean convertLangStrings) {
        JsonParser parser = new JsonParser();
        if (isMessage(message.getText())) {
            JsonObject object = parser.parse(message.getText()).getAsJsonObject();
            message = Message.fromJson(formatJson(object));
        }

        String messageText = message.getText();
        if (convertLangStrings) {
            messageText = getLangConversion(messageText);
        }

        StringBuilder builder = new StringBuilder(messageText);
        for (Message msg : message.getExtra()) {
            builder.append(getFormat(msg.getStyle().getFormats()));
            builder.append(getColor(msg.getStyle().getColor()));
            if (!(msg.getText() == null)) {
                builder.append(getBedrockMessage(msg));
            }
        }
        return builder.toString();
    }

    private static String getLangConversion(String messageText) {
        return LANG_MAPPINGS.getOrDefault(messageText, messageText);
    }

    public static String getBedrockMessage(Message message) {
        return getBedrockMessageWithTranslate(message, false);
    }

    private static String getColor(ChatColor color) {
        String base = "\u00a7";
        switch (color) {
            case BLACK:
                base += "0";
                break;
            case DARK_BLUE:
                base += "1";
                break;
            case DARK_GREEN:
                base += "2";
                break;
            case DARK_AQUA:
                base += "3";
                break;
            case DARK_RED:
                base += "4";
                break;
            case DARK_PURPLE:
                base += "5";
                break;
            case GOLD:
                base += "6";
                break;
            case GRAY:
                base += "7";
                break;
            case DARK_GRAY:
                base += "8";
                break;
            case BLUE:
                base += "9";
                break;
            case GREEN:
                base += "a";
                break;
            case AQUA:
                base += "b";
                break;
            case RED:
                base += "c";
                break;
            case LIGHT_PURPLE:
                base += "d";
                break;
            case YELLOW:
                base += "e";
                break;
            case WHITE:
                base += "f";
                break;
            case RESET:
            case NONE:
                base += "r";
                break;
            default:
                return "";
        }

        return base;
    }

    private static String getFormat(List<ChatFormat> formats) {
        StringBuilder str = new StringBuilder();
        for (ChatFormat cf : formats) {
            String base = "\u00a7";
            switch (cf) {
                case OBFUSCATED:
                    base += "k";
                    break;
                case BOLD:
                    base += "l";
                    break;
                case STRIKETHROUGH:
                    base += "m";
                    break;
                case UNDERLINED:
                    base += "n";
                    break;
                case ITALIC:
                    base += "o";
                    break;
                default:
                    return "";
            }

            str.append(base);
        }

        return str.toString();
    }

    public static boolean isMessage(String text) {
        JsonParser parser = new JsonParser();
        try {
            JsonObject object = parser.parse(text).getAsJsonObject();
            try {
                Message.fromJson(formatJson(object));
            } catch (Exception ex) {
                return false;
            }
        } catch (Exception ex) {
            return false;
        }
        return true;
    }

    public static JsonObject formatJson(JsonObject object) {
        if (object.has("hoverEvent")) {
            JsonObject sub = (JsonObject) object.get("hoverEvent");
            JsonElement element = sub.get("value");

            if (element instanceof JsonArray) {
                JsonObject newobj = new JsonObject();
                newobj.add("extra", element);
                newobj.addProperty("text", "");
                sub.remove("value");
                sub.add("value", newobj);
            }
        }

        if (object.has("extra")) {
            JsonArray a = object.getAsJsonArray("extra");
            for (int i = 0; i < a.size(); i++) {
                if (!(a.get(i) instanceof JsonPrimitive))
                    formatJson((JsonObject) a.get(i));
            }
        }
        return object;
    }

    public static String toChatColor(TeamColor teamColor) {
        for (ChatColor color : ChatColor.values()) {
            if (color.name().equals(teamColor.name())) {
                return getColor(color);
            }
        }
        for (ChatFormat format : ChatFormat.values()) {
            if (format.name().equals(teamColor.name())) {
                return getFormat(Collections.singletonList(format));
            }
        }
        return "";
    }
}
