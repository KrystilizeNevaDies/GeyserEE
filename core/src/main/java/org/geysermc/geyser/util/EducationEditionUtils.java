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
//        TokenManager.INSTANCE.createInitialToken("https://login.microsoftonline.com/common/oauth2/nativeclient?code=0.AW4AFchlF7Q7RE-i49nEKJqFrjIUa7McGoJMm3Yk3hyrQvJuAKM.AgABAAIAAAD--DLA3VO7QrddgJg7WevrAgDs_wQA9P-2sl-iisN-TChyQ3bn3ieqY-SiB9V8UnSWS-B2WpEgv3sqp5caaDUyqlC7lCnuD0w1zvqYPhW-DMGk14bt-WB85bGECgszCAC_bd4g-8a7S_FgrXUrtuYH9lcPaa1oQibZiDwirMRFNeGgoPfWWULGvKBa_RxVrcRhVuSTRjwp2mFjRXDJD_bnMz8V5jizmXnEaCE-6odwBvU_bX1bs9Ww4A6pSixHoUWCOaqa2RN8uvzvSpKxoXzS3rLeCDo3_71PoijrCzfbe2OMw9iG-2pH7H4JspAAxflJ3nTMjneh-GnEMkBvfOzPrKgwB4LLMKVLDxB7gMpd2ggwf__NimsCB1jp0dFIb6bGmM1gWiIQemh5OT9zGoXm3gg7-Wd8VGb8ZNRtmA5bBNPrMzHJnvJ0ipi2EZunYkDW-2WCYMhiLzeGgRddOSGkW5zm2eEoztgWI_afeE95t8zlzCZ2FRWzOd1PaLydU1LnmI8y3sFvbQe3XxKIVN9igRiodf_2oBAVDEDVBh9yIQso9cLEoJvOy6_hkXn7WNbKOmm10o7Ceyg8qMR5lbIISwEJSKR2KuOEzwCeEnK8Sp3EX3BGg83JCFGHFy-oAUAUOaJrhDCEWPnWgW-Ly9Tx9ddBhfr2bMlf13qXmhgA_th_oI164XELTA&state=e84f479c-acb6-4039-807d-00e2abcd6dc9&session_state=b0e604e6-2b9e-49df-89fd-316ad94301df");
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