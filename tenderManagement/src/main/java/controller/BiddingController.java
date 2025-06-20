package controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import model.BiddingModel;
import service.BiddingService;

@RestController
@RequestMapping("/bidding")
public class BiddingController {
	
	@PostMapping("/add")
	public ResponseEntity<Object> postBidding(@RequestBody BiddingModel biddingModel){
		return BiddingService.postBidding(biddingModel);
	}
	
//	@PostMapping("/register")
//	public Users register(@RequestBody Users user) {
//		return service.register(user);
//	}
	
//	@GetMapping
//	
//	
//	
//	@PatchMapping
//	
//	
//	@DeleteMapping
	

}
