package model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class RoleModel {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;
	@Column(unique = true)
	private String rolename;
	
	
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getRolename() {
		return rolename;
	}
	public void setRolename(String rolename) {
		this.rolename = rolename;
	}
	public RoleModel(int id, String rolename) {
		this.id = id;
		this.rolename = rolename;
	}
	public RoleModel() {
		super();
		// TODO Auto-generated constructor stub
	}
	public RoleModel(int id) {
		this.id=id;
	}
	
	public RoleModel(String rolename) {
		this.rolename=rolename;
	}
	
//	public RoleModel(int id, String rolename) {
//		this.id=id;
//		this.rolename=rolename;
//	}
	
	@Override
	public String toString() {
		return "RoleModel [id=" + id + ", rolename=" + rolename + "]";
	}

	
	
}
