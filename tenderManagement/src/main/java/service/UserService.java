package service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import model.UserModel;
import repository.RoleRepository;
import repository.UserRepository;


@Service
public class UserService {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private RoleRepository roleRepository;
	
	
	public UserModel getUserByEmail(String email) {
		return userRepository.findByEmail(email);
	}

}
