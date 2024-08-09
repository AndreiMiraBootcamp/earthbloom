package es.animal.hogar.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import es.animal.hogar.entities.Favorite;
import es.animal.hogar.services.FavoriteService;

@RestController
@RequestMapping("/protected/api/favorites")
public class FavoriteController {

    @Autowired
    private FavoriteService favoriteService;

    @PostMapping
    public ResponseEntity<Favorite> createFavorite(@RequestBody Favorite favorite) {
        Favorite createdFavorite = favoriteService.createFavorite(favorite);
        return ResponseEntity.ok(createdFavorite);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Favorite> updateFavorite(@PathVariable Integer id, @RequestBody Favorite favoriteDetails) {
        Favorite favorite = favoriteService.getFavoriteById(id);
        if (favorite == null) {
            return ResponseEntity.notFound().build();
        }

        favorite.setPet(favoriteDetails.getPet());
        favorite.setUser(favoriteDetails.getUser()); // Cambiado de `setAdopter` a `setUser`
        favorite.setCreatedAt(favoriteDetails.getCreatedAt());

        Favorite updatedFavorite = favoriteService.updateFavorite(favorite);
        return ResponseEntity.ok(updatedFavorite);
    }

    @PatchMapping("/{id}")
    public ResponseEntity<Favorite> patchFavorite(@PathVariable Integer id, @RequestBody Favorite favoriteDetails) {
        Favorite favorite = favoriteService.patchFavorite(id, favoriteDetails);
        if (favorite == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(favorite);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteFavorite(@PathVariable Integer id) {
        Favorite favorite = favoriteService.getFavoriteById(id);
        if (favorite == null) {
            return ResponseEntity.notFound().build();
        }

        favoriteService.deleteFavorite(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Favorite> getFavoriteById(@PathVariable Integer id) {
        Favorite favorite = favoriteService.getFavoriteById(id);
        if (favorite == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(favorite);
    }

    @GetMapping
    public ResponseEntity<List<Favorite>> getAllFavorites() {
        List<Favorite> favorites = favoriteService.getAllFavorites();
        return ResponseEntity.ok(favorites);
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<Favorite>> getFavoritesByUserId(@PathVariable Integer userId) {
        List<Favorite> favorites = favoriteService.getFavoritesByUserId(userId);
        return ResponseEntity.ok(favorites);
    }

    @GetMapping("/pet/{petId}")
    public ResponseEntity<List<Favorite>> getFavoritesByPetId(@PathVariable Integer petId) {
        List<Favorite> favorites = favoriteService.getFavoritesByPetId(petId);
        return ResponseEntity.ok(favorites);
    }
}