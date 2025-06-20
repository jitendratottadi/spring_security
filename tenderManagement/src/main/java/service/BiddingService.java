package service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import model.BiddingModel;
import model.UserModel;
import repository.BiddingRepository;
import repository.UserRepository;

@Service
public class BiddingService {
	
	@Autowired
	private UserService userService;
	
	@Autowired
	UserRepository userrepository;

	@Autowired
	private BiddingRepository biddingRepository;
	
	public static ResponseEntity<Object> postBidding(BiddingModel biddingModel) {
		// TODO Auto-generated method stub
		
		try {
			String email = getCurrentUserEmail();
			UserModel user= userService.getUserByEmail(email);
			
			if(!"BIDDER".equals(user.getRole().getRolename())) {
				return new ResponseEntity<>("Forbidden", HttpStatus.FORBIDDEN);
			}
			
			biddingModel.setBidderId(user.getId());
			biddingModel.setDateOfBidding(getCurrentDate());
			
			biddingRepository.save(biddingModel);
			return new ResponseEntity<>(biddingModel, HttpStatus.CREATED);
		} catch (Exception e) {
			// TODO: handle exception
			return new ResponseEntity<>("Bad Request", HttpStatus.BAD_REQUEST);
		}
	}

	private static String getCurrentUserEmail() {
		// TODO Auto-generated method stub
		return null;
	}

}
