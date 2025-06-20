package repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import model.BiddingModel;

@Repository
public interface BiddingRepository extends JpaRepository<BiddingModel, Integer> {
	List<BiddingModel> findByBidAmountGreaterThan(double bidAmount);
	
	

}
