import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';

import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}

  // REGISTER
  async register(data: RegisterDto) {
    const email = data.email.toLowerCase();

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('Email sudah terdaftar');
    }

    const hashedPassword = await bcrypt.hash(data.password, 10);

    const user = await this.prisma.user.create({
      data: {
        name: data.name,
        email,
        password: hashedPassword,
        role: data.role,
      },
    });

    return {
      message: 'Registrasi berhasil',
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    };
  }

  // LOGIN
  async login(data: LoginDto) {
    const email = data.email.toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Email atau password salah');
    }

    const isMatch = await bcrypt.compare(
      data.password,
      user.password,
    );

    if (!isMatch) {
      throw new UnauthorizedException('Email atau password salah');
    }

    // CUSTOMER tidak mendapatkan token
    if (user.role !== 'ADMIN') {
      return {
        message: 'Login berhasil',
        data: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      };
    }

    // Token hanya dibuat untuk ADMIN
    const token = await this.jwt.signAsync({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    return {
      message: 'Login berhasil',
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        token,
      },
    };
  }

  // GET ALL PROFILE
  async getAllProfile() {
    const users = await this.prisma.user.findMany({
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        createdAt: true,
      },
    });

    return {
      message: 'Berhasil mengambil semua data user',
      data: users,
    };
  }

  // GET PROFILE BERDASARKAN ID
  async getProfile(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User tidak ditemukan');
    }

    return {
      message: 'Berhasil mengambil profil',
      data: user,
    };
  }

  // EDIT PROFILE
  async updateProfile(
    id: number,
    data: UpdateProfileDto,
  ) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('User tidak ditemukan');
    }

    if (data.email) {
      const email = data.email.toLowerCase();

      const existingUser = await this.prisma.user.findUnique({
        where: { email },
      });

      if (existingUser && existingUser.id !== id) {
        throw new ConflictException('Email sudah digunakan');
      }

      data.email = email;
    }

    const updatedUser = await this.prisma.user.update({
      where: { id },
      data,
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
      },
    });

    return {
      message: 'Profil berhasil diperbarui',
      data: updatedUser,
    };
  }

  // DELETE PROFILE
  async deleteProfile(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('User tidak ditemukan');
    }

    await this.prisma.user.delete({
      where: { id },
    });

    return {
      message: 'User berhasil dihapus',
    };
  }
}