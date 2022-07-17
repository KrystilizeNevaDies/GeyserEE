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

import java.sql.*;
import java.util.Locale;

public class LocalLoginUtil {

    // The SQLite database
    private static final Connection connection;

    static {
        Connection conn;
        try {
            String URL = "jdbc:sqlite:logins.db";

            conn = DriverManager.getConnection(URL);
            conn.getMetaData(); // I think this is used to create the database initially?

            String CREATE_TABLE = """
                    CREATE TABLE IF NOT EXISTS logins (
                     username text PRIMARY KEY,
                     password int NOT NULL
                    );""";

            Statement stmt = conn.createStatement();
            stmt.execute(CREATE_TABLE);
        } catch (SQLException e) {
            throw new RuntimeException("Failed to connect to local login database", e);
        }

        connection = conn;
    }

    /**
     * Checks if this login exists
     * @param username The username to check
     * @param password The password to check
     * @return True if the login exists, false if not
     */
    public static boolean hasLogin(String username, String password) {
        String QUERY = "SELECT * FROM logins WHERE username = ? AND password = ?";

        int passHash = password.hashCode();

        try {
            PreparedStatement stmt = connection.prepareStatement(QUERY);
            stmt.setString(1, username.toLowerCase(Locale.ROOT));
            stmt.setInt(2, passHash);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return true;
            }
        } catch (SQLException e) {
            // expected
        }
        return false;
    }

    /**
     * Inserts the login
     * @param username The username to insert
     * @param password The password to insert
     */
    public static void insertLocally(String username, String password) {
        String INSERT = "INSERT INTO logins(username, password) VALUES(?,?)";

        int passHash = password.hashCode();

        try {
            PreparedStatement stmt = connection.prepareStatement(INSERT);
            stmt.setString(1, username.toLowerCase(Locale.ROOT));
            stmt.setInt(2, passHash);
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to insert login", e);
            // expected
        }
    }

    public static boolean hasUsername(String username) {
        String QUERY = "SELECT * FROM logins WHERE username = ?";

        try {
            PreparedStatement stmt = connection.prepareStatement(QUERY);
            stmt.setString(1, username.toLowerCase(Locale.ROOT));
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return true;
            }
        } catch (SQLException e) {
            // expected
        }
        return false;
    }
}
