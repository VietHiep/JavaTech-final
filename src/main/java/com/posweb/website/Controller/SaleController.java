package com.posweb.website.Controller;

import com.posweb.website.Model.Customer;
import com.posweb.website.Model.Order;
import com.posweb.website.Model.Product;
import com.posweb.website.Model.User;
import com.posweb.website.Repository.UserRepo;
import com.posweb.website.Service.CustomerService;
import com.posweb.website.Service.ImageUtils;
import com.posweb.website.Service.OrderService;
import com.posweb.website.Service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Controller
@RequestMapping("/salesperson")
public class SaleController {

    @Autowired
    private UserRepo repo;

    @Autowired
    private ProductService productService;

    @Autowired
    private CustomerService customerService;

    @Autowired
    private OrderService orderService;

    @PostMapping("/logout")
    public String logout(HttpServletRequest request)
    {
        request.getSession().invalidate();
        return "redirect:/login";
    }

    @GetMapping("")
    public String getSalesperson(Model model)
    {

        List<Product> productList = productService.getAllProducts();
        model.addAttribute("imageUtils", new ImageUtils());
        model.addAttribute("products", productList);
        return "viewProductSale_page";
    }

    @PostMapping("")
    public String Salesperson(Model model)
    {
        return "viewProductSale_page";
    }

    @GetMapping("/profile")
    public String getProfile(Model model, HttpSession session) throws IOException
    {
        List<Product> productList = productService.getAllProducts();
        model.addAttribute("imageUtils", new ImageUtils());
        User loggedInUser = (User) session.getAttribute("loggedInUser");
        if (loggedInUser != null) {
            model.addAttribute("user", loggedInUser);
            return "salesperson_page";
        } else {
            return "redirect:/login";
        }
    }

    @PostMapping("/profile")
    public String Profile(Model model)
    {
        return "salesperson_page";
    }


    @GetMapping("/update-avatar")
    public String updateAvatar(Model model, HttpSession session)
    {
        User loggedInUser = (User) session.getAttribute("loggedInUser");
        if (loggedInUser != null) {
            model.addAttribute("user", loggedInUser);
            return "updateAvatar_page";
        } else {
            return "redirect:/login";
        }
    }

    @PostMapping("/update-avatar")
    public String updateAvatar(@RequestParam("avatar") MultipartFile avatar,
                               HttpSession session,
                               RedirectAttributes redirectAttributes) throws IOException
    {
        User loggedInUser = (User) session.getAttribute("loggedInUser");
        if (loggedInUser != null) {
            if (!avatar.isEmpty()) {
                byte[] imageBytes = avatar.getBytes();
                loggedInUser.setPicture(imageBytes);
                repo.save(loggedInUser);
                redirectAttributes.addFlashAttribute("successMessage", "Avatar updated successfully!");
            } else {
                redirectAttributes.addFlashAttribute("errorMessage", "Please select an image to upload.");
            }
            return "redirect:/salesperson/profile"; // Redirect back to the salesperson page
        } else {
            return "redirect:/login";
        }
    }

    //------------------GET DEFAULT AVATAR AND ENCODE BYTE--------------------------
    @ModelAttribute("base64Image")
    public String base64Image(Model model, HttpSession session)
    {
        User loggedInUser = (User) session.getAttribute("loggedInUser");
        if (loggedInUser != null && loggedInUser.getPicture() != null) {
            return Base64.getEncoder().encodeToString(loggedInUser.getPicture());
        }
        return "";
    }
    //================================================================================

    @GetMapping("/checkout")
    public String showCheckoutCounter(Model model) {
        model.addAttribute("customer", new Customer());
        model.addAttribute("product", new Product());
        return "checkoutCounter_page";
    }

    @PostMapping("/checkout")
    public String processCheckout(@ModelAttribute Customer customer, Model model)
    {
        Customer existingCustomer = customerService.findCustomerByPhoneNumber(customer.getPhoneNumber());
        if (existingCustomer != null) {
            model.addAttribute("existingCustomer", existingCustomer);
        } else {
            customerService.save(customer);
        }
        return "redirect:/salesperson";
    }
//    @PostMapping("/checkout")
//    public String processCheckout(@RequestParam("productId") int productId,
//                                  @RequestParam("quantity") int quantity,
//                                  @ModelAttribute Customer customer,
//                                  Model model,
//                                  HttpSession session) {
//
//        // Retrieve existing customer by phone number
//        Customer existingCustomer = customerService.findCustomerByPhoneNumber(customer.getPhoneNumber());
//
//        // Validate if the customer is existing
//        if (existingCustomer != null) {
//            model.addAttribute("existingCustomer", existingCustomer);
//        } else {
//            // Save the new customer
//            customerService.save(customer);
//        }
//
//        // Retrieve the list of purchased products from the session
//        List<Product> purchasedProducts = (List<Product>) session.getAttribute("purchasedProducts");
//
//        // Initialize the list if it doesn't exist
//        if (purchasedProducts == null) {
//            purchasedProducts = new ArrayList<>();
//        }
//
//        // Retrieve product details by product ID (adjust as needed based on your application)
//        Product product = productService.findById(productId);
//
//        // Validate if the product exists
//        if (product != null) {
//            // Set the quantity entered by the salesperson
////            product.setQuantity(5);
//            purchasedProducts.add(product);
//            // Save the updated list in the session
//            session.setAttribute("purchasedProducts", purchasedProducts);
//
//            // Add the list of purchased products to the model for display
//            model.addAttribute("purchasedProducts", purchasedProducts);
//        } else {
//            // Handle the case where the product is not found
//            model.addAttribute("productNotFound", true);
//        }
//
//        return "checkoutCounter_page"; // Return the same page to display the list of purchased products
//}

    @GetMapping("/customers")
    public String showCustomerList(Model model)
    {
        List<Customer> customerList = customerService.findAll();
        model.addAttribute("customerList", customerList);
        return "list_of_customers";
    }

    @GetMapping("/purchase-history")
    public String showPurchaseHistory(@RequestParam("customerId") int customerId, Model model) {
        Customer customer = customerService.findCustomerById(customerId);
        if (customer != null) {
            List<Order> purchaseHistoryList = orderService.findOrdersByCustomer(customer);
            model.addAttribute("customer", customer);
            model.addAttribute("purchaseHistoryList", purchaseHistoryList);
            return "purchase_history";
        } else {
            return "redirect:/salesperson/customers";
        }
    }

}
