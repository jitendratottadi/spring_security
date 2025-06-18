package model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;

@Entity
public class UserModel {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="id")
	private int id;
	@Column(name="UserName")
	private String userName;
	@Column(name="CompanyName")
	private String companyName;
	@Column(name="Password")
	private String password;
	@Column(name="email", unique = true)
	private String email;
	@OneToOne
	@JoinColumn(name="role", referencedColumnName = "id")
	private RoleModel role;
	
	
	
	
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
	public String getCompanyName() {
		return companyName;
	}
	public void setCompanyName(String companyName) {
		this.companyName = companyName;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public RoleModel getRole() {
		return role;
	}
	public void setRole(RoleModel role) {
		this.role = role;
	}
	@Override
	public String toString() {
		return "UserModel [id=" + id + ", userName=" + userName + ", companyName=" + companyName + ", password="
				+ password + ", email=" + email + ", role=" + role + "]";
	}
	public UserModel(int id, String userName, String companyName, String password, String email, RoleModel role) {
		super();
		this.id = id;
		this.userName = userName;
		this.companyName = companyName;
		this.password = password;
		this.email = email;
		this.role = role;
	}
	public UserModel() {
		super();
		// TODO Auto-generated constructor stub
	}
	
	

}
