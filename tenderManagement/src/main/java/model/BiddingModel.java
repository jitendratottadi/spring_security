package model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class BiddingModel {
	
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	private int id;
	@Column(unique=true)
	private int biddingid;
	private final String projectName="Metro phase v 2024";
	private Double bidAmount;
	private Double yearsToComplete;
	private String dateOfBidding;
	private String status="pending";
	private int bidderId;
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public int getBiddingid() {
		return biddingid;
	}
	public void setBiddingid(int biddingid) {
		this.biddingid = biddingid;
	}
	public Double getBidAmount() {
		return bidAmount;
	}
	public void setBidAmount(Double bidAmount) {
		this.bidAmount = bidAmount;
	}
	public Double getYearsToComplete() {
		return yearsToComplete;
	}
	public void setYearsToComplete(Double yearsToComplete) {
		this.yearsToComplete = yearsToComplete;
	}
	public String getDateOfBidding() {
		return dateOfBidding;
	}
	public void setDateOfBidding(String dateOfBidding) {
		this.dateOfBidding = dateOfBidding;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public int getBidderId() {
		return bidderId;
	}
	public void setBidderId(int bidderId) {
		this.bidderId = bidderId;
	}
	public String getProjectName() {
		return projectName;
	}
	public BiddingModel(int id, int biddingid, Double bidAmount, Double yearsToComplete, String dateOfBidding,
			String status, int bidderId) {
		super();
		this.id = id;
		this.biddingid = biddingid;
		this.bidAmount = bidAmount;
		this.yearsToComplete = yearsToComplete;
		this.dateOfBidding = dateOfBidding;
		this.status = status;
		this.bidderId = bidderId;
	}
	public BiddingModel() {
		super();
		// TODO Auto-generated constructor stub
	}
	@Override
	public String toString() {
		return "BiddingModel [id=" + id + ", biddingid=" + biddingid + ", projectName=" + projectName + ", bidAmount="
				+ bidAmount + ", yearsToComplete=" + yearsToComplete + ", dateOfBidding=" + dateOfBidding + ", status="
				+ status + ", bidderId=" + bidderId + "]";
	}
	
	
	

}
