package repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import model.BiddingModel;
import model.RoleModel;

@Repository
public interface BiddingRepository extends JpaRepository<BiddingModel, Integer> {
	List<BiddingModel> findByBidAmountGreaterThan(double bidAmount);
	
	//RoleModel findbyRolename(String rolename);
	BiddingModel findByBiddingId(Integer biddingId);
	
	

}
