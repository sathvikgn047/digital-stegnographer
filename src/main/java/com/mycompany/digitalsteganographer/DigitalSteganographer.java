import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Base64;

public class DigitalSteganographer extends JFrame {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/steganography_db";
    private static final String DB_USER = "your_db_user";
    private static final String DB_PASSWORD = "your_db_password";

    private JTextArea messageTextArea;
    private JPasswordField passwordField;
    private JLabel imagePathLabel;
    private File selectedImageFile;

    public DigitalSteganographer() {
        setTitle("Digital Steganographer");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 400);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));

        JPanel mainPanel = new JPanel();
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        mainPanel.setLayout(new BorderLayout(10, 10));

        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        gbc.gridx = 0;
        gbc.gridy = 0;
        formPanel.add(new JLabel("Secret Message:"), gbc);

        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridheight = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        messageTextArea = new JTextArea(5, 20);
        messageTextArea.setLineWrap(true);
        messageTextArea.setWrapStyleWord(true);
        formPanel.add(new JScrollPane(messageTextArea), gbc);
        gbc.gridheight = 1;
        gbc.weighty = 0;


        gbc.gridx = 0;
        gbc.gridy = 2;
        formPanel.add(new JLabel("Password:"), gbc);

        gbc.gridx = 1;
        gbc.gridy = 2;
        passwordField = new JPasswordField();
        formPanel.add(passwordField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 3;
        JButton selectImageButton = new JButton("Select Image");
        formPanel.add(selectImageButton, gbc);

        gbc.gridx = 1;
        gbc.gridy = 3;
        imagePathLabel = new JLabel("No image selected.");
        formPanel.add(imagePathLabel, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        JButton encodeButton = new JButton("Encode");
        JButton decodeButton = new JButton("Decode");
        buttonPanel.add(encodeButton);
        buttonPanel.add(decodeButton);

        mainPanel.add(formPanel, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        add(mainPanel);

        selectImageButton.addActionListener(e -> selectImage());
        encodeButton.addActionListener(e -> process(true));
        decodeButton.addActionListener(e -> process(false));

        DatabaseManager.init();
    }

    private void selectImage() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Image files", "png", "bmp"));
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            selectedImageFile = fileChooser.getSelectedFile();
            imagePathLabel.setText(selectedImageFile.getName());
        }
    }

    private void process(boolean isEncode) {
        if (selectedImageFile == null) {
            JOptionPane.showMessageDialog(this, "Please select an image first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String password = new String(passwordField.getPassword());
        if (password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Password cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (isEncode) {
            String message = messageTextArea.getText();
            if (message.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Message cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            encodeImage(message, password);
        } else {
            decodeImage(password);
        }
    }

    private void encodeImage(String message, String password) {
        try {
            BufferedImage originalImage = ImageIO.read(selectedImageFile);
            String encryptedMessage = CryptoCore.encrypt(message, password);
            BufferedImage stegoImage = StegoCore.embed(originalImage, encryptedMessage);

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Save Stego Image");
            fileChooser.setSelectedFile(new File("stego-image.png"));
            int userSelection = fileChooser.showSaveDialog(this);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();
                ImageIO.write(stegoImage, "png", fileToSave);
                JOptionPane.showMessageDialog(this, "Message hidden successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                DatabaseManager.logOperation("ENCODE", selectedImageFile.getAbsolutePath(), fileToSave.getAbsolutePath(), message.length());
                messageTextArea.setText("");
                passwordField.setText("");
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Encoding failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void decodeImage(String password) {
        try {
            BufferedImage stegoImage = ImageIO.read(selectedImageFile);
            String encryptedMessage = StegoCore.extract(stegoImage);
            String decryptedMessage = CryptoCore.decrypt(encryptedMessage, password);
            messageTextArea.setText(decryptedMessage);
            JOptionPane.showMessageDialog(this, "Message extracted successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
            DatabaseManager.logOperation("DECODE", selectedImageFile.getAbsolutePath(), null, decryptedMessage.length());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Decoding failed. Check password or image integrity.", "Error", JOptionPane.ERROR_MESSAGE);
            ex.printStackTrace(); // Helpful for debugging
        }
    }

    private static class StegoCore {
        private static final int STEGO_MARKER = 0x5A5A5A5A;

        public static BufferedImage embed(BufferedImage image, String data) {
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            int dataLength = dataBytes.length;
            int capacity = (image.getWidth() * image.getHeight() * 3) / 2;
            if (dataLength + 8 > capacity) {
                throw new IllegalArgumentException("Message is too large for the selected image.");
            }

            BufferedImage newImage = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_INT_ARGB);
            newImage.getGraphics().drawImage(image, 0, 0, null);

            byte[] stegoMarkerBytes = ByteBuffer.allocate(4).putInt(STEGO_MARKER).array();
            byte[] lengthBytes = ByteBuffer.allocate(4).putInt(dataLength).array();

            byte[] payload = new byte[stegoMarkerBytes.length + lengthBytes.length + dataBytes.length];
            System.arraycopy(stegoMarkerBytes, 0, payload, 0, stegoMarkerBytes.length);
            System.arraycopy(lengthBytes, 0, payload, stegoMarkerBytes.length, lengthBytes.length);
            System.arraycopy(dataBytes, 0, payload, stegoMarkerBytes.length + lengthBytes.length, dataBytes.length);

            int payloadIndex = 0;
            int nibbleIndex = 0;

            for (int y = 0; y < image.getHeight() && payloadIndex < payload.length; y++) {
                for (int x = 0; x < image.getWidth() && payloadIndex < payload.length; x++) {
                    int pixel = newImage.getRGB(x, y);
                    int alpha = (pixel >> 24) & 0xFF;
                    int red = (pixel >> 16) & 0xFF;
                    int green = (pixel >> 8) & 0xFF;
                    int blue = pixel & 0xFF;

                    if (payloadIndex < payload.length) {
                        red = embedNibble(red, payload[payloadIndex], nibbleIndex++);
                        if (nibbleIndex > 1) {
                            nibbleIndex = 0;
                            payloadIndex++;
                        }
                    }
                    if (payloadIndex < payload.length) {
                        green = embedNibble(green, payload[payloadIndex], nibbleIndex++);
                        if (nibbleIndex > 1) {
                            nibbleIndex = 0;
                            payloadIndex++;
                        }
                    }
                    if (payloadIndex < payload.length) {
                        blue = embedNibble(blue, payload[payloadIndex], nibbleIndex++);
                        if (nibbleIndex > 1) {
                            nibbleIndex = 0;
                            payloadIndex++;
                        }
                    }

                    int newPixel = (alpha << 24) | (red << 16) | (green << 8) | blue;
                    newImage.setRGB(x, y, newPixel);
                }
            }
            return newImage;
        }

        private static int embedNibble(int color, byte data, int nibbleIndex) {
            int nibble = (nibbleIndex == 0) ? (data >> 4) & 0x0F : data & 0x0F;
            return (color & 0xF0) | nibble;
        }

        public static String extract(BufferedImage image) {
            byte[] headerBytes = new byte[8];
            int byteIndex = 0;
            int nibbleIndex = 0;
            byte currentByte = 0;

            for (int y = 0; y < image.getHeight() && byteIndex < 8; y++) {
                for (int x = 0; x < image.getWidth() && byteIndex < 8; x++) {
                    int pixel = image.getRGB(x, y);

                    if (byteIndex < 8) {
                        currentByte = assembleByte(currentByte, (pixel >> 16) & 0xFF, nibbleIndex++);
                        if (nibbleIndex > 1) {
                            headerBytes[byteIndex++] = currentByte;
                            currentByte = 0;
                            nibbleIndex = 0;
                        }
                    }
                    if (byteIndex < 8) {
                        currentByte = assembleByte(currentByte, (pixel >> 8) & 0xFF, nibbleIndex++);
                        if (nibbleIndex > 1) {
                            headerBytes[byteIndex++] = currentByte;
                            currentByte = 0;
                            nibbleIndex = 0;
                        }
                    }
                    if (byteIndex < 8) {
                        currentByte = assembleByte(currentByte, pixel & 0xFF, nibbleIndex++);
                        if (nibbleIndex > 1) {
                            headerBytes[byteIndex++] = currentByte;
                            currentByte = 0;
                            nibbleIndex = 0;
                        }
                    }
                }
            }

            int marker = ByteBuffer.wrap(headerBytes, 0, 4).getInt();
            if (marker != STEGO_MARKER) {
                throw new IllegalStateException("No hidden message found (invalid stego marker).");
            }

            int dataLength = ByteBuffer.wrap(headerBytes, 4, 4).getInt();
            if (dataLength <= 0 || dataLength > (long) image.getWidth() * image.getHeight() * 3 / 2) {
                throw new IllegalStateException("Invalid data length detected.");
            }

            byte[] dataBytes = new byte[dataLength];
            byteIndex = 0;
            nibbleIndex = 0;
            currentByte = 0;
            
            int startPixelIndex = (8 * 2) / 3;
            int channelsToSkip = (8 * 2) % 3;

            for (int i = startPixelIndex; i < image.getWidth() * image.getHeight() && byteIndex < dataLength; i++) {
                int x = i % image.getWidth();
                int y = i / image.getWidth();
                int pixel = image.getRGB(x, y);

                int red = (pixel >> 16) & 0xFF;
                int green = (pixel >> 8) & 0xFF;
                int blue = pixel & 0xFF;

                if (i == startPixelIndex) {
                    if(channelsToSkip == 1) { // R is used, G is first
                        currentByte = assembleByte(currentByte, green, nibbleIndex++);
                        if(nibbleIndex > 1) { dataBytes[byteIndex++] = currentByte; currentByte = 0; nibbleIndex = 0; }
                    }
                    if(byteIndex < dataLength) {
                        currentByte = assembleByte(currentByte, blue, nibbleIndex++);
                        if(nibbleIndex > 1) { dataBytes[byteIndex++] = currentByte; currentByte = 0; nibbleIndex = 0; }
                    }
                } else {
                     if (byteIndex < dataLength) {
                        currentByte = assembleByte(currentByte, red, nibbleIndex++);
                        if (nibbleIndex > 1) { dataBytes[byteIndex++] = currentByte; currentByte = 0; nibbleIndex = 0; }
                    }
                     if (byteIndex < dataLength) {
                        currentByte = assembleByte(currentByte, green, nibbleIndex++);
                        if (nibbleIndex > 1) { dataBytes[byteIndex++] = currentByte; currentByte = 0; nibbleIndex = 0; }
                    }
                     if (byteIndex < dataLength) {
                        currentByte = assembleByte(currentByte, blue, nibbleIndex++);
                        if (nibbleIndex > 1) { dataBytes[byteIndex++] = currentByte; currentByte = 0; nibbleIndex = 0; }
                    }
                }
            }
            return new String(dataBytes, StandardCharsets.UTF_8);
        }

        private static byte assembleByte(byte currentByte, int color, int nibbleIndex) {
            int nibble = color & 0x0F;
            if (nibbleIndex == 0) {
                return (byte) (nibble << 4);
            } else {
                return (byte) (currentByte | nibble);
            }
        }
    }

    private static class CryptoCore {
        private static final String ALGORITHM = "AES/GCM/NoPadding";
        private static final int TAG_LENGTH_BIT = 128;
        private static final int IV_LENGTH_BYTE = 12;
        private static final int SALT_LENGTH_BYTE = 16;

        public static String encrypt(String plainText, String password) throws Exception {
            byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);
            byte[] iv = getRandomNonce(IV_LENGTH_BYTE);

            SecretKey aesKey = getAESKeyFromPassword(password.toCharArray(), salt);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            byte[] cipherTextWithIvSalt = ByteBuffer.allocate(salt.length + iv.length + cipherText.length)
                    .put(salt)
                    .put(iv)
                    .put(cipherText)
                    .array();

            return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);
        }

        public static String decrypt(String cText, String password) throws Exception {
            byte[] decode = Base64.getDecoder().decode(cText.getBytes(StandardCharsets.UTF_8));
            ByteBuffer bb = ByteBuffer.wrap(decode);

            byte[] salt = new byte[SALT_LENGTH_BYTE];
            bb.get(salt);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            bb.get(iv);
            byte[] cipherText = new byte[bb.remaining()];
            bb.get(cipherText);

            SecretKey aesKey = getAESKeyFromPassword(password.toCharArray(), salt);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        }

        private static byte[] getRandomNonce(int numBytes) {
            byte[] nonce = new byte[numBytes];
            new SecureRandom().nextBytes(nonce);
            return nonce;
        }

        private static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
                throws NoSuchAlgorithmException, InvalidKeySpecException {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        }
    }

    private static class DatabaseManager {
        public static void init() {
            try {
                Class.forName("com.mysql.cj.jdbc.Driver");
            } catch (ClassNotFoundException e) {
                System.err.println("MySQL JDBC Driver not found. Add it to your classpath.");
            }
        }

        public static void logOperation(String type, String originalPath, String stegoPath, int messageLength) {
            String sql = "INSERT INTO operations_log (operation_type, original_image_path, stego_image_path, message_length, timestamp) VALUES (?, ?, ?, ?, ?)";
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                 PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setString(1, type);
                pstmt.setString(2, originalPath);
                pstmt.setString(3, stegoPath);
                pstmt.setInt(4, messageLength);
                pstmt.setTimestamp(5, new Timestamp(System.currentTimeMillis()));
                pstmt.executeUpdate();

            } catch (SQLException e) {
                System.err.println("Database logging failed: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            new DigitalSteganographer().setVisible(true);
        });
    }
}

