import Mailgen from "mailgen";
import nodemailer from "nodemailer";

const sendMail = async (options) => {
    const mailGenerator = new Mailgen(
        {
            theme: "default",
            product: {
                name: "Project Manager",
                link: "https://projectmanager.com/",
            }
        }
    )

    const emailText = mailGenerator.generatePlaintext(options.mailgenContent);
    const emailHTML = mailGenerator.generate(options.mailgenContent);

    const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_SMTP_HOST,
        port: process.env.MAILTRAP_SMTP_PORT,
        secure: false,
        auth: {
            user: process.env.MAILTRAP_SMTP_USER,
            pass: process.env.MAILTRAP_SMTP_PASSWORD,
        }
    });

    const mailOptions = {
        from: "Project Manager <projectmanager@example.com>",
        to: options.to,
        subject: options.subject,
        text: emailText,
        html: emailHTML
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log("Email sent:", info.messageId);
    } catch (error) {
        console.error("Error sending email:", error);
    }
}

const emailVerificationMailgenContent = (username, veficationURL) => {
    return {
        body: {
            name: username,
            intro: "Welcome to Project Manager! We're very excited to have you on board.",
            action: {
                instructions: "To get started with your account, please click here:",
                button: {
                    color: "#22BC66", // Optional action button color 
                    text: "Verify Email",
                    link: veficationURL
                }
            },
            outro: "Need help, or have questions? Just reply to this email, we'd love to help."
        }
    }
}

const forgotPasswordMailgenContent = (username, passwordResetURL) => {
    return {
        body: {
            name: username,
            intro: "You have received this email because a password reset request for your account was received.",
            action: {
                instructions: "Click the button below to reset your password:",
                button: {
                    color: "#DC4D2F", // Optional action button color 
                    text: "Reset Password",
                    link: passwordResetURL
                }
            },
            outro: "If you did not request a password reset, no further action is required on your part."
        }
    }
}

export { sendMail, emailVerificationMailgenContent, forgotPasswordMailgenContent };