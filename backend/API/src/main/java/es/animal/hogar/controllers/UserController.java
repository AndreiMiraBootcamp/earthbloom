package es.animal.hogar.controllers;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import es.animal.hogar.dtos.UserDTO;
import es.animal.hogar.entities.User;
import es.animal.hogar.services.UserService;

@RestController
@RequestMapping("/protected/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping(consumes = { "multipart/form-data" })
    public ResponseEntity<?> createUser(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam("email") String email,
            @RequestParam("role") String role,
            @RequestParam("phoneNumber") String phoneNumber,
            @RequestParam("address") String address,
            @RequestParam("city") String city,
            @RequestParam("state") String state,
            @RequestParam("postalCode") Integer postalCode,
            @RequestParam("image") MultipartFile image) {

        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        user.setEmail(email);
        user.setRole(User.Role.valueOf(role));
        user.setPhoneNumber(phoneNumber);
        user.setAddress(address);
        user.setCity(city);
        user.setState(state);
        user.setPostalCode(postalCode);

        try {
            user.setImage(image.getBytes());
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to process image");
        }

        User savedUser = userService.createUser(user);
        return ResponseEntity.ok().body("User created successfully with ID: " + savedUser.getUserId());
    }

    @PutMapping(value = "/{id}", consumes = { "multipart/form-data" })
    public ResponseEntity<?> updateUser(
            @PathVariable Integer id,
            @RequestPart("username") String username,
            @RequestPart("password") String password,
            @RequestPart("email") String email,
            @RequestPart("role") String role,
            @RequestPart("phoneNumber") String phoneNumber,
            @RequestPart("address") String address,
            @RequestPart("city") String city,
            @RequestPart("state") String state,
            @RequestPart("postalCode") Integer postalCode,
            @RequestPart(value = "image", required = false) MultipartFile image) {

        User user = new User();
        user.setUserId(id);
        user.setUsername(username);
        user.setPassword(password);
        user.setEmail(email);
        user.setRole(User.Role.valueOf(role));
        user.setPhoneNumber(phoneNumber);
        user.setAddress(address);
        user.setCity(city);
        user.setState(state);
        user.setPostalCode(postalCode);
        
        if (image != null && !image.isEmpty()) {
            try {
                user.setImage(image.getBytes());
            } catch (IOException e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to process image");
            }
        }

        User updatedUser = userService.updateUser(user);

        return ResponseEntity.ok().body("User updated successfully with ID: " + updatedUser.getUserId());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Integer id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Integer id, @RequestParam(value = "dto", defaultValue = "true") boolean useDTO) {
        if (useDTO) {
            UserDTO userDTO = userService.getUserDTOById(id);
            return userDTO != null ? ResponseEntity.ok(userDTO) : ResponseEntity.notFound().build();
        } else {
            User user = userService.getUserById(id);
            return user != null ? ResponseEntity.ok(user) : ResponseEntity.notFound().build();
        }
    }

    @GetMapping
    public ResponseEntity<?> getAllUsers(@RequestParam(value = "dto", defaultValue = "true") boolean useDTO) {
        if (useDTO) {
            List<UserDTO> userDTOs = userService.getAllUserDTOs();
            return ResponseEntity.ok(userDTOs);
        } else {
            List<User> users = userService.getAllUsers();
            return ResponseEntity.ok(users);
        }
    }

    @GetMapping("/username/{username}")
    public ResponseEntity<?> getUserByUsername(@PathVariable String username, @RequestParam(value = "dto", defaultValue = "true") boolean useDTO) {
        if (useDTO) {
            UserDTO userDTO = userService.getUserDTOByUsername(username);
            return userDTO != null ? ResponseEntity.ok(userDTO) : ResponseEntity.notFound().build();
        } else {
            User user = userService.getUserByUsername(username);
            return user != null ? ResponseEntity.ok(user) : ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<?> getUserByEmail(@PathVariable String email, @RequestParam(value = "dto", defaultValue = "true") boolean useDTO) {
        if (useDTO) {
            UserDTO userDTO = userService.getUserDTOByEmail(email);
            return userDTO != null ? ResponseEntity.ok(userDTO) : ResponseEntity.notFound().build();
        } else {
            User user = userService.getUserByEmail(email);
            return user != null ? ResponseEntity.ok(user) : ResponseEntity.notFound().build();
        }
    }

    @PatchMapping(value = "/{id}", consumes = { "multipart/form-data" })
    public ResponseEntity<?> patchUser(
            @PathVariable Integer id,
            @RequestPart(value = "username", required = false) String username,
            @RequestPart(value = "password", required = false) String password,
            @RequestPart(value = "email", required = false) String email,
            @RequestPart(value = "role", required = false) String role,
            @RequestPart(value = "phoneNumber", required = false) String phoneNumber,
            @RequestPart(value = "address", required = false) String address,
            @RequestPart(value = "city", required = false) String city,
            @RequestPart(value = "state", required = false) String state,
            @RequestPart(value = "postalCode", required = false) Integer postalCode,
            @RequestPart(value = "image", required = false) MultipartFile image) {

        User user = new User();
        user.setUserId(id);
        if (username != null) user.setUsername(username);
        if (password != null) user.setPassword(password);
        if (email != null) user.setEmail(email);
        if (role != null) user.setRole(User.Role.valueOf(role));
        if (phoneNumber != null) user.setPhoneNumber(phoneNumber);
        if (address != null) user.setAddress(address);
        if (city != null) user.setCity(city);
        if (state != null) user.setState(state);
        if (postalCode != null) user.setPostalCode(postalCode);
        if (image != null && !image.isEmpty()) {
            try {
                user.setImage(image.getBytes());
            } catch (IOException e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to process image");
            }
        }

        User updatedUser = userService.patchUser(user);

        return ResponseEntity.ok().body("User patched successfully with ID: " + updatedUser.getUserId());
    }
}