package configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import model.RoleModel;
import model.UserModel;
import repository.RoleRepository;
import repository.UserRepository;

@Component
public class DataLoader  implements ApplicationRunner{
	
	@Autowired
	private RoleRepository roleRepository;
	
	@Autowired
	private UserRepository userRepository;
	
	public void run(ApplicationArguments arguments) throws InterruptedException {
		
		roleRepository.save(new RoleModel("BIDDER"));
		roleRepository.save(new RoleModel("APPROVER"));
		
		/*	public UserModel(int id, String userName,
		String companyName, String password,
		String email, RoleModel role) {*/

//		userRepository.save(new UserModel(1,"bidder1","companyone"
//				,"bidder123","bidderemail1@gmail.com", RoleModel role));
		
		userRepository.save(new UserModel(1, "bidder1", "companyone", "bidder1", "bidder1@gmail.com", null));
		userRepository.save(new UserModel(2, "bidder2", "companytwo", "bidder12", "bidder2@gmail.com", null));
		userRepository.save(new UserModel(3, "bidder3", "companythree", "bidder123", "bidder3@gmail.com", null));
	}
	
	

}
