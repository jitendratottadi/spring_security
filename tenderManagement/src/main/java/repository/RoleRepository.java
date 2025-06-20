package repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import model.RoleModel;

@Repository
public interface RoleRepository  extends JpaRepository<RoleModel, Integer> {
	
	RoleModel findbyRolename(String rolename);

}
