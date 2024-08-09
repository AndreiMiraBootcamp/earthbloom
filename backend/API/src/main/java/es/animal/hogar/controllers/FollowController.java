package es.animal.hogar.controllers;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import es.animal.hogar.entities.Follow;
import es.animal.hogar.services.FollowService;

@RestController
@RequestMapping("/protected/api/follows")
public class FollowController {

    @Autowired
    private FollowService followService;

    @PostMapping
    public ResponseEntity<Follow> createFollow(@RequestBody Map<String, Map<String, Integer>> body) {
        Integer userId = body.get("user").get("userId");
        Integer centerId = body.get("center").get("centerId");
        
        Follow createdFollow = followService.createFollow(userId, centerId);
        return ResponseEntity.ok(createdFollow);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Follow> updateFollow(@PathVariable Integer id, @RequestBody Follow followDetails) {
        Follow follow = followService.getFollowById(id);
        if (follow == null) {
            return ResponseEntity.notFound().build();
        }

        follow.setUser(followDetails.getUser());
        follow.setCenter(followDetails.getCenter());
        follow.setCreatedAt(followDetails.getCreatedAt());

        Follow updatedFollow = followService.updateFollow(follow);
        return ResponseEntity.ok(updatedFollow);
    }

    @PatchMapping("/{id}")
    public ResponseEntity<Follow> patchFollow(@PathVariable Integer id, @RequestBody Follow followDetails) {
        Follow follow = followService.patchFollow(id, followDetails);
        if (follow == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(follow);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteFollow(@PathVariable Integer id) {
        Follow follow = followService.getFollowById(id);
        if (follow == null) {
            return ResponseEntity.notFound().build();
        }

        followService.deleteFollow(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Follow> getFollowById(@PathVariable Integer id) {
        Follow follow = followService.getFollowById(id);
        if (follow == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(follow);
    }

    @GetMapping
    public ResponseEntity<List<Follow>> getAllFollows() {
        List<Follow> follows = followService.getAllFollows();
        return ResponseEntity.ok(follows);
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<Follow>> getFollowsByUserId(@PathVariable Integer userId) {
        List<Follow> follows = followService.getFollowsByUserId(userId);
        return ResponseEntity.ok(follows);
    }

    @GetMapping("/center/{centerId}")
    public ResponseEntity<List<Follow>> getFollowsByCenterId(@PathVariable Integer centerId) {
        List<Follow> follows = followService.getFollowsByCenterId(centerId);
        return ResponseEntity.ok(follows);
    }
}