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

package org.geysermc.geyser.menu;

import org.geysermc.cumulus.CustomForm;
import org.geysermc.cumulus.SimpleForm;
import org.geysermc.geyser.session.GeyserSession;
import org.geysermc.geyser.skin.SkinProvider;
import org.jetbrains.annotations.NotNull;

public class SystemMenus {

    private final String username;
    private final GeyserSession session;

    public SystemMenus(@NotNull String username, @NotNull GeyserSession session) {
        this.username = username;
        this.session = session;
    }

    public void main() {
        session.sendForm(SimpleForm.builder()
                .title("Main Menu")
                .button("Start")
                .button("Options")
                .button("Exit")
                .responseHandler((form, responseData) -> {
                    var response = form.parseResponse(responseData);
                    if (response.isClosed()) {
                        session.disconnect("Goodbye!");
                    }

                    switch (response.getClickedButtonId()) {
                        case 0 -> connectDownstream();
                        case 1 -> options();
                        case 2 -> session.disconnect("Goodbye!");
                    }
                }));
    }

    public void options() {
        session.sendForm(CustomForm.builder()
                .title("Options")
                .label("For help with this list, contact the developer.")
                .responseHandler((form, responseData) -> {
                    var response = form.parseResponse(responseData);

                    if (response.isClosed()) {
                        main();
                        return;
                    }

                    if (response.isInvalid()) {
                        options();
                        return;
                    }

                    // TODO: Read options

                    main();
                }));

    }

    private void connectDownstream() {
        session.continueDownstream(username);
    }
}
