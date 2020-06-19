import {
  InternalServerErrorException,
  ConflictException,
} from '@nestjs/common';
import { Repository, EntityRepository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from './user.entity';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';

@EntityRepository(User)
export class UserRepository extends Repository<User> {
  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    const { username, password } = authCredentialsDto;

    const user = new User();
    user.username = username;
    user.salt = await bcrypt.genSalt();
    user.password = await this.hashPassowrd(password, user.salt);

    console.log(user.password);
    try {
      await user.save();
    } catch (error) {
      if (error.code === '23505') {
        // 23505 code for duplicate unique value(username here)
        throw new ConflictException('Username already exists');
        // will return status code 409 - Conflict
      } else {
        // will return status code 500 - Internal error
        throw new InternalServerErrorException();
      }
    }
  }

  async validateUserPassword(
    authCredentialsDto: AuthCredentialsDto,
  ): Promise<string> {
    const { username, password } = authCredentialsDto;
    const user = await this.findOne({ username });
    if (user && (await user.validatePassword(password))) {
      return user.username;
    } else {
      return null;
    }
  }

  private async hashPassowrd(password: string, salt: string): Promise<string> {
    return bcrypt.hash(password, salt);
  }
}
