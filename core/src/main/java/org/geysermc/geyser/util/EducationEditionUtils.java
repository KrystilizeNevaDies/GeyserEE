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

import org.geysermc.geyser.text.ChatColor;

public class EducationEditionUtils {

    public static void main(String[] args) throws TokenManager.TokenException {
//        usageNew();
        TokenManager.INSTANCE.createInitialToken("");
        System.out.println(TokenManager.INSTANCE.getTokenMap());
    }

    private static void waitForInput() {
        String input = System.console().readLine();

        if ("education new".equals(input)) {
            usageNew();
        } else {
            if (input.startsWith("education confirm ")) {
                input = input.replace("education confirm ", "");
                try {
                    TokenManager.INSTANCE.createInitialToken(input);
                } catch (TokenManager.TokenException e) {
                    throw new RuntimeException(e);
                }
            } else {
                showHelp();
            }
        }
    }

    private static void showHelp() {
        System.out.println("---- Education SubCommands ----");
        System.out.println("/education new    - Create new Authorization URL");
        System.out.println("/education confirm    - Confirm an Authorization Response");
        System.out.println();
        System.out.println("Use 'new' to generate a URL that you copy into your browser.");
        System.out.println("This will allow you to log into your MCEE account. Once done you will have a white page with a URL both in");
        System.out.println("its title as well as address bar. Copy the full address and provide it as a parameter to 'confirm'.");
    }

    private static void usageNew() {
        System.out.println("Copy and paste the following into your web browser:");
        String url = String.valueOf(TokenManager.INSTANCE.getNewAuthorizationUrl());
        System.out.println();
        System.out.println(url);
    }

}