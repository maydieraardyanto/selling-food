import {
  Controller,
  Post,
  Body,
  Get,
  Patch,
  Delete,
  UseGuards,
  Param,
} from '@nestjs/common';

import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';

import { AuthGuard } from '@nestjs/passport';
import { Roles } from './decorators/roles.decorators';
import { RolesGuard } from './guard/roles.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // REGISTER
  @Post('register')
  register(@Body() data: RegisterDto) {
    return this.authService.register(data);
  }

  // LOGIN
  @Post('login')
  login(@Body() data: LoginDto) {
    return this.authService.login(data);
  }

  // GET PROFILE - ADMIN ONLY
  @Get('profile/:id')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles('ADMIN')
  getProfile(@Param('id') id: string) {
    return this.authService.getProfile(Number(id));
  }

  // EDIT PROFILE - ADMIN ONLY
  @Patch('profile/:id')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles('ADMIN')
  updateProfile(
    @Param('id') id: string,
    @Body() data: UpdateProfileDto,
  ) {
    return this.authService.updateProfile(Number(id), data);
  }

  // DELETE PROFILE - ADMIN ONLY
  @Delete('profile/:id')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles('ADMIN')
  deleteProfile(@Param('id') id: string) {
    return this.authService.deleteProfile(Number(id));
  }
}