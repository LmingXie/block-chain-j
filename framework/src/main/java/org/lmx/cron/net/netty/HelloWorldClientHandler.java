package org.lmx.cron.net.netty;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import lombok.extern.slf4j.Slf4j;

/**
 * 功能描述: 客户端管道处理器
 *
 * @author LM.X
 * @date 2020/4/7 12:04
 */
@Slf4j
public class HelloWorldClientHandler extends ChannelInboundHandlerAdapter {

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        log.info("客户端管道处理器状态：存活……");
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        log.info("客户端管道处理器 收到消息：{}", msg);
    }


    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ctx.close();
        log.info(" 客户端管道处理器 Netty 异常：{}", cause);
    }

}