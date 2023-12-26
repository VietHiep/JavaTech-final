package com.posweb.website.Controller;

import com.posweb.website.Model.ChangePasswordForm;
import com.posweb.website.Model.ConfirmationToken;
import com.posweb.website.Model.PasswordChangeRequest;
import com.posweb.website.Model.User;
import com.posweb.website.Repository.ConfirmationTokenRepo;
import com.posweb.website.Repository.UserRepo;
import com.posweb.website.Service.EmailService;
import com.posweb.website.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;

@Controller
@RequestMapping("")
public class UserController {

    private String tokentemp;
    @Value("${base_url}")
    private String baseUrl;
    @Autowired
    private UserService userService;
    @Autowired
    private EmailService emailService;
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private ConfirmationTokenRepo confirmationTokenRepo;

    @ModelAttribute("changePasswordForm")
    public ChangePasswordForm changePasswordForm() {
        return new ChangePasswordForm();
    }

    public UserController(UserService userService, EmailService emailService) {
        this.userService = userService;
        this.emailService = emailService;
    }

    // -----------------------------------LOG
    // IN-----------------------------------Done
    @GetMapping("/login")
    public String getLoginPage(Model model, HttpSession session) {
        if (session.getAttribute("loggedInUser") != null) {
            return "redirect:/admin";
        }
        model.addAttribute("loginRequest", new User());
        return "account/login";
    }

    @PostMapping("/login")
    public String login(@ModelAttribute User user, RedirectAttributes redirectAttributes, HttpSession session) {
        User authenticate = userService.authenticate(user.getUsername(), user.getPassword());
        if (authenticate != null) {
            session.setAttribute("loggedInUser", authenticate);
            if (authenticate.isEnable()) {
                if (authenticate.getRole().equals("ADMIN")) {
                    return "redirect:/admin";
                } else if (authenticate.getRole().equals("SALE")) {
                    return "redirect:/salesperson";
                } else {
                    redirectAttributes.addFlashAttribute("loginError", "Invalid role");
                    return "redirect:/login";
                }
            } else {
                redirectAttributes.addFlashAttribute("loginError", "Account has not been verified");
                return "redirect:/login";
            }
        } else {
            redirectAttributes.addFlashAttribute("loginError", "Login failed, please check your username and password");
            return "redirect:/login";
        }
    }
    // ###########################------------------------###############################

    // -----------------------------------LOG
    // OUT-----------------------------------Done
    @PostMapping("/logout")
    public String logout(HttpServletRequest request) {
        request.getSession().invalidate();
        return "redirect:/login";
    }
    // ###########################------------------------###############################

    // -----------------------------------CHANGE
    // PASSWORD---------------------------Done
    @GetMapping("/changePassword")
    public String getChangePasswordPage(Model model) {
        model.addAttribute("changepasswordRequest", new User());
        return "account/changePassword";
    }

    @PostMapping("/changePassword")
    public String changePassword(@ModelAttribute PasswordChangeRequest request, RedirectAttributes redirectAttributes) {

        UserService.ChangePasswordResult result = userService.changePassword(request);
        switch (result) {
            case SUCCESS:
                redirectAttributes.addFlashAttribute("message", "Change Password successfully");
                return "redirect:/login";
            case SAME_PASSWORD:
                redirectAttributes.addFlashAttribute("error",
                        "The new password must be different from the old password");
                return "redirect:/changePassword";
            case USER_NOT_FOUND:
                redirectAttributes.addFlashAttribute("error", "Username is not exist");
                return "redirect:/changePassword";
            default:
                redirectAttributes.addFlashAttribute("error", "Failed to change password. Please try again.");
                return "redirect:/changePassword";
        }
    }
    // ###########################------------------------###############################

    // ----------------------------CREATE AND CONFIRM SALEPERSON
    // ACCOUNT------------------------Done
    @RequestMapping(value = "/createAccount", method = RequestMethod.GET)
    public ModelAndView getCreateAccount(ModelAndView modelAndView, User user) {
        modelAndView.addObject("user", user);
        modelAndView.setViewName("account/admin/createAccount_page");
        return modelAndView;
    }

    @RequestMapping(value = "/createAccount", method = RequestMethod.POST)
    public ModelAndView createAccount(ModelAndView modelAndView, User user) throws IOException {
        User existingUser = userRepo.findByEmailIgnoreCase(user.getEmail());
        if (existingUser != null) {
            modelAndView.addObject("message", "This email already exists!");
            modelAndView.setViewName("error/error_page");
        } else {

            // Split and set user's account
            String mail = user.getEmail();
            String split_mail[] = mail.split("@");
            String user_name = split_mail[0];
            String user_password_temp = split_mail[0];

            user.setUsername(user_name);
            user.setPassword(user_password_temp);
            user.setEnable(false);
            user.setRole("SALE");
            String imagePath = "src/main/resources/static/image/anonymous_avatar.png";
            byte[] imageBytes = getImageBytes(imagePath);
            user.setPicture(imageBytes);

            userRepo.save(user);
            ConfirmationToken confirmationToken = new ConfirmationToken(user);

            confirmationTokenRepo.save(confirmationToken);
            SimpleMailMessage mailMessage = new SimpleMailMessage();
            mailMessage.setTo(mail);
            mailMessage.setSubject("Complete Registration!");
            mailMessage.setFrom("hiepgale0817@gmail.com");
            mailMessage.setText("Your account has been created, this is the link to log in to the system : "
                    + baseUrl + "/confirmAccount?token=" + confirmationToken.getConfirmationToken());

            emailService.sendEmail(mailMessage);

            modelAndView.addObject("email", "Email has been sent");
            modelAndView.setViewName("account/admin/createAccount_page");
        }
        return modelAndView;
    }

    @RequestMapping(value = "/confirmAccount", method = RequestMethod.GET)
    public ModelAndView getChangePassword(ModelAndView modelAndView, @RequestParam("token") String confirmationToken) {
        ConfirmationToken token = confirmationTokenRepo.findByConfirmationToken(confirmationToken);
        tokentemp = confirmationToken;

        if (token != null && !token.isUsed() && !isTokenExpired(token)) {
            modelAndView.addObject("confirmationToken", confirmationToken);
            modelAndView.setViewName("account/createPassword_page");
        } else {
            // Token is invalid or has been used, show an error message
            modelAndView.addObject("message", "The link is invalid or has already been used!");
            modelAndView.setViewName("error/error_page");
        }
        return modelAndView;
    }

    @PostMapping("/confirmAccount")
    public ModelAndView changePassword(ModelAndView modelAndView, @ModelAttribute ChangePasswordForm form) {

        ConfirmationToken token = confirmationTokenRepo.findByConfirmationToken(tokentemp);

        if (token != null) {
            User user = userRepo.findByEmailIgnoreCase(token.getUser().getEmail());
            if (form.getNewPassword().equals(form.getConfirmPassword())) {
                // Update the user's password
                token.setUsed(true);
                confirmationTokenRepo.save(token);
                user.setEnable(true);
                UserService.ChangePasswordResult result = userService.changePasswordForNewSale(user,
                        form.getNewPassword());
                if (result == UserService.ChangePasswordResult.SUCCESS) {
                    // Password changed successfully, redirect to /salesperson
                    modelAndView.setViewName("redirect:/salesperson");
                } else {
                    // Password change failed, show an error message
                    modelAndView.addObject("message", "Failed to change the password.");
                    modelAndView.setViewName("error/error_page");
                }
            } else {
                // Passwords do not match, show an error message
                modelAndView.addObject("message", "Passwords do not match.");
                modelAndView.setViewName("error/error_page");
            }
        } else {
            // Token is invalid or broken, show an error message
            modelAndView.addObject("message", "The token has been used!");
            modelAndView.setViewName("error/error_page");
        }
        return modelAndView;
    }

    // Check expired token
    private boolean isTokenExpired(ConfirmationToken token) {
        return token.getCreatedDate() != null && token.getCreatedDate().before(new Date());
    }

    private byte[] getImageBytes(String imagePath) throws IOException {
        Path path = Paths.get(imagePath);
        return Files.readAllBytes(path);
    }
}
