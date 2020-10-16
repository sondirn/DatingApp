import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { ReplaySubject } from 'rxjs/internal/ReplaySubject';
import { map } from 'rxjs/operators';
import { User } from '../_models/User';

@Injectable({
  providedIn: 'root'
})
export class AccountService {
  baseUrl = 'https://localhost:5001/api/';
  private currentUserSource = new ReplaySubject<User>(1);
  currentUser$ = this.currentUserSource.asObservable();

  constructor(private http: HttpClient) { }

  login(model: any){
    return this.http.post(this.baseUrl + 'account/login', model).pipe(
      map((response: User) => {
        const user = response;
        if(user){
          this.setCurrentUser(user);
        }
      })
    )
  }

  register(model: any){
    return this.http.post(this.baseUrl + 'account/register', model).pipe(
      map((user: User) => {
        if(user) {
          this.setCurrentUser(user);
        }
        return user
      })
    )
  }

  setCurrentUser(user: User) {
    localStorage.setItem('user', JSON.stringify(user));
    this.currentUserSource.next(user);
  }

  logout() : void {
    localStorage.removeItem('user');
    this.currentUserSource.next(null);
  }
}
